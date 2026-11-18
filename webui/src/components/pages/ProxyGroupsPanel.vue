<script setup lang="ts">
import { t } from "@/i18n";
import { computed, onActivated, onBeforeUnmount, onDeactivated, ref, watch } from "vue";
import { Copy, RefreshCw, Route } from "lucide-vue-next";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import ConfirmPanel from "@/components/ui/ConfirmPanel.vue";
import InsightChip from "@/components/ui/InsightChip.vue";
import SearchField from "@/components/ui/SearchField.vue";
import { buildNodeDelayStats, nodeDelayQualityLabel, parseNodeTestAll, sanitizeNodeText, type NodeDelayEntry } from "@/composables/nodeDelayParsers";
import { parseProxyGroupsSnapshot, sanitizeProxyName, type ProxyGroupSummary } from "@/composables/proxyGroupParsers";
import { useActionLock } from "@/composables/useActionLock";
import { useMagicNet } from "@/composables/useMagicNet";
import { useVisibilityTask } from "@/composables/useVisibilityTask";
import { copyText, execFailed, shellQuote } from "@/utils";
import { buildProxySelectionPlan, formatProxySelectionPlanReport, type ProxySelectionPlan } from "./proxySelectionPlan";
import { matchingProxyGroups, matchingProxyGroupNodes, proxyDisplayName, proxyNameLabel } from "./proxyGroupView";

type PendingProxyAction = {
  group: ProxyGroupSummary;
  node: string;
  run: () => Promise<void>;
};

const { runCli, state } = useMagicNet();
const { isRunning, withAction } = useActionLock();
const rawOutput = ref("");
const copied = ref(false);
const groupQuery = ref("");
const groupDelays = ref(new Map<string, NodeDelayEntry[]>());
const pendingAction = ref<PendingProxyAction | null>(null);
const selectionPlanCopied = ref(false);
const groupLimit = ref(8);
const nodeLimits = ref(new Map<string, number>());
let active = true;
let disposed = false;
let activatedOnce = false;
let snapshotVersion = 0;
let refreshQueued = false;

const snapshot = computed(() => parseProxyGroupsSnapshot(rawOutput.value));
const pendingPlan = computed<ProxySelectionPlan | null>(() => {
  const action = pendingAction.value;
  if (!action) return null;
  return buildProxySelectionPlan(action.group, action.node, groupDelays.value.get(action.group.name) || []);
});
const filteredGroups = computed(() => matchingProxyGroups(snapshot.value?.groups || [], groupQuery.value));
const visibleGroups = computed(() => filteredGroups.value.slice(0, groupLimit.value));
watch(groupQuery, () => {
  groupLimit.value = 8;
  nodeLimits.value = new Map();
});

function currentRead(version: number): boolean {
  return active && !disposed && version === snapshotVersion;
}

function publishGroups(output: string): void {
  rawOutput.value = output;
  copied.value = false;
  selectionPlanCopied.value = false;
  groupDelays.value.clear();
  // Keep search and expansion drafts; only cancel a choice that is no longer valid.
  const action = pendingAction.value;
  if (action) {
    const group = parseProxyGroupsSnapshot(output)?.groups.find((entry) => entry.name === action.group.name);
    pendingAction.value = group?.proxies.includes(action.node) && group.now !== action.node
      ? { ...action, group } : null;
  }
}

async function refreshGroups(): Promise<void> {
  if (!active || disposed) return;
  if (isRunning("proxy-groups-refresh")) {
    refreshQueued = true;
    return;
  }
  refreshQueued = false;
  try {
    await withAction("proxy-groups-refresh", async () => {
      const version = ++snapshotVersion;
      const output = await runCli("api proxies", t("读取代理组"));
      if (currentRead(version)) publishGroups(output);
    });
  } finally {
    // A return to the page during an older read still needs one fresh observation.
    if (refreshQueued && active && !disposed) void refreshGroups();
  }
}

function requestSelect(group: ProxyGroupSummary, node: string): void {
  if (!validProxyChoice(group.name, node)) {
    state.output = t("代理组或节点名称为空/过长，已拒绝执行。");
    return;
  }
  pendingAction.value = {
    group,
    node,
    run: () => selectNode(group.name, node)
  };
  selectionPlanCopied.value = false;
}

function validProxyChoice(group: string, node: string): boolean {
  return Boolean(group.trim() && node.trim() && group.length <= 180 && node.length <= 240);
}

async function testGroup(group: ProxyGroupSummary): Promise<void> {
  const nodes = group.proxies.slice(0, 16);
  if (!nodes.length) return;
  await withAction(`proxy-group-test-${group.name}`, async () => {
    const version = snapshotVersion;
    const output = await runCli(`node test-all ${nodes.map(shellQuote).join(" ")}`, t("测速 {name}", { name: group.name }));
    if (!currentRead(version)) return;
    const requested = new Set(nodes);
    const entries = parseNodeTestAll(output).filter((entry) => requested.has(entry.node));
    groupDelays.value.set(group.name, entries);
  });
}

function requestUseFastest(group: ProxyGroupSummary): void {
  const fastest = groupDelayStats(group).fastest;
  if (!fastest) {
    state.output = t("请先测速本组，且至少需要一个可用节点。");
    return;
  }
  requestSelect(group, fastest.node);
}

function groupDelayStats(group: ProxyGroupSummary) {
  return buildNodeDelayStats(groupDelays.value.get(group.name) || []);
}

function visibleGroupNodes(group: ProxyGroupSummary): string[] {
  return matchingProxyGroupNodes(group, groupQuery.value).slice(0, nodeLimits.value.get(group.name) ?? 9);
}

function remainingGroupNodes(group: ProxyGroupSummary): number {
  return matchingProxyGroupNodes(group, groupQuery.value).length - visibleGroupNodes(group).length;
}

function showMoreNodes(group: ProxyGroupSummary): void {
  nodeLimits.value.set(group.name, (nodeLimits.value.get(group.name) ?? 9) + 9);
}

async function selectNode(group: string, node: string): Promise<void> {
  await withAction("proxy-groups-select", async () => {
    const version = ++snapshotVersion;
    const text = await runCli(`api select ${shellQuote(group)} ${shellQuote(node)}`, t("切换代理节点"));
    if (execFailed(text) || !currentRead(version)) return;
    state.output = text;
    const refreshed = await runCli("api proxies", t("刷新代理组"), true);
    if (!currentRead(version)) return;
    if (execFailed(refreshed)) {
      state.output = t("代理节点切换已执行，但代理组刷新未确认：\n{refreshed}", { refreshed: refreshed });
      return;
    }
    publishGroups(refreshed);
  });
}

function cancelAction(): void {
  pendingAction.value = null;
  selectionPlanCopied.value = false;
}

async function confirmAction(): Promise<void> {
  const action = pendingAction.value;
  if (!action) return;
  try {
    await action.run();
  } finally {
    pendingAction.value = null;
    selectionPlanCopied.value = false;
  }
}

async function copySelectionPlan(): Promise<void> {
  const action = pendingAction.value;
  const plan = pendingPlan.value;
  if (!action || !plan) return;
  selectionPlanCopied.value = await copyText(formatProxySelectionPlanReport(plan));
  state.output = selectionPlanCopied.value ? t("代理切换计划摘要已复制。") : t("剪贴板不可用，代理切换计划未复制。");
}

async function copyReport(): Promise<void> {
  const report = visibleGroups.value.flatMap((group) => {
    const stats = groupDelayStats(group);
    const delays = groupDelays.value.get(group.name) || [];
    return [
      `${sanitizeProxyName(group.name)} type=${group.type} now=${sanitizeProxyName(group.now || "none")} count=${group.proxies.length}`,
      `delay_tested=${stats.tested} usable=${stats.usable} failed=${stats.failed} median_ms=${stats.medianMillis ?? "none"} parsed_usable_percent=${stats.usablePercent} fastest=${stats.fastest ? `${sanitizeNodeText(stats.fastest.node)} ${sanitizeNodeText(stats.fastest.summary)}` : "none"}`,
      ...visibleGroupNodes(group).map((node) => {
        const delay = delays.find((entry) => entry.node === node);
        return `  - ${sanitizeProxyName(node)}${delay ? ` delay=${sanitizeNodeText(delay.summary)} quality=${delay.quality}` : ""}`;
      })
    ];
  }).join("\n");
  copied.value = await copyText(report);
  state.output = copied.value ? t("代理组报告已复制。") : t("剪贴板不可用，代理组报告未复制。");
}

const { target: visibilityTarget, started: observationStarted } = useVisibilityTask(refreshGroups);
onActivated(() => {
  active = true;
  // The first visible load belongs to useVisibilityTask; do not duplicate it.
  if (activatedOnce && observationStarted.value) void refreshGroups();
  activatedOnce = true;
});
onDeactivated(() => {
  active = false;
  snapshotVersion += 1;
  refreshQueued = false;
});
onBeforeUnmount(() => {
  active = false;
  disposed = true;
  snapshotVersion += 1;
  refreshQueued = false;
});
</script>

<template>
  <div ref="visibilityTarget" class="mn-deferred-region">
    <Card class="proxy-groups-surface grid gap-5">
    <div class="proxy-groups-toolbar flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0">
        <h3 class="inline-flex items-center gap-2 text-base font-semibold"><Route :size="17" /> {{ t("代理组") }}</h3>

      </div>
      <div class="flex gap-2">
        <Button size="sm" variant="outline" :loading="isRunning('proxy-groups-refresh')" @click="refreshGroups">
          <RefreshCw :size="15" />{{ t("刷新") }} </Button>
        <Button size="sm" variant="secondary" :disabled="!visibleGroups.length" @click="copyReport">
          <Copy :size="15" />{{ copied ? t("已复制") : t("复制") }}
        </Button>
      </div>
    </div>

    <div class="proxy-groups-search grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <SearchField v-model="groupQuery" :placeholder="t('搜索代理组或节点')" />
      <span class="text-sm text-[var(--mn-ink-muted)]">
        {{ t("{visible} / {total} 组", { visible: visibleGroups.length, total: filteredGroups.length }) }} </span>
    </div>

    <ConfirmPanel
      v-if="pendingAction"
      :title="t('切换代理节点')"
      :detail="`${proxyDisplayName(pendingAction.group.name)}：${sanitizeProxyName(pendingPlan?.summary || '')}`"
      command="api select <group> <node>"
      :loading="isRunning('proxy-groups-select')"
      :confirm-label="t('确认切换')"
      confirm-variant="secondary"
      @cancel="cancelAction"
      @confirm="confirmAction"
    >
      <div class="mt-3 flex flex-wrap gap-2">
        <InsightChip
          v-for="item in pendingPlan?.items || []"
          :key="item.label"
          :label="t(item.label)"
          :value="sanitizeProxyName(item.value)"
          :tone="item.tone"
        />
      </div>
      <p v-if="pendingPlan?.warnings.length" class="mt-2 text-xs leading-5 text-[var(--mn-warning)]/80">
        {{ pendingPlan.warnings.join("; ") }}
      </p>
      <template #actions>
        <Button size="sm" variant="outline" @click="cancelAction">{{ t("取消") }}</Button>
        <Button size="sm" variant="outline" @click="copySelectionPlan">{{ selectionPlanCopied ? t("已复制计划") : t("复制计划") }}</Button>
        <Button size="sm" variant="secondary" :loading="isRunning('proxy-groups-select')" @click="confirmAction">{{ t("确认切换") }}</Button>
      </template>
    </ConfirmPanel>

    <div v-if="visibleGroups.length" class="proxy-groups-list grid gap-8">
      <section v-for="group in visibleGroups" :key="group.name" class="proxy-group min-w-0 border-t border-[var(--mn-border)] pt-6">
        <div class="proxy-group-heading mb-3 min-w-0">
          <div class="min-w-0">
            <h4 class="break-words text-base font-semibold text-[var(--mn-ink)]">{{ proxyNameLabel(group.name) }}</h4>
            <p v-if="proxyNameLabel(group.name) !== sanitizeProxyName(group.name)" class="break-words text-xs text-[var(--mn-ink-muted)]">{{ sanitizeProxyName(group.name) }}</p>
            <p class="text-xs text-[var(--mn-ink-muted)]">{{ group.type }} · {{ t("{count} 个节点", { count: group.proxies.length }) }}</p>
          </div>
          <p class="proxy-current-choice mt-2 break-words text-sm text-[var(--mn-ink-soft)]">
            <span class="text-[var(--mn-ink-muted)]">{{ t("当前选择") }} · </span><strong>{{ proxyDisplayName(group.now || t("未选择")) }}</strong>
          </p>
        </div>
        <div class="proxy-group-tools mb-2 grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-center">
          <p class="text-xs text-[var(--mn-ink-muted)]">
            <template v-if="groupDelayStats(group).tested"> {{ t("已测 {tested} · 可用 {usable} · 最快 {fastest}", { tested: groupDelayStats(group).tested, usable: groupDelayStats(group).usable, fastest: groupDelayStats(group).fastest?.summary || t("无") }) }}
            </template>
            <template v-else>{{ t("可测速本组前 16 个节点。") }}</template>
          </p>
          <Button size="sm" variant="outline" :loading="isRunning(`proxy-group-test-${group.name}`)" @click="testGroup(group)">{{ t("测速本组") }}</Button>
          <Button size="sm" variant="secondary" :disabled="!groupDelayStats(group).fastest" @click="requestUseFastest(group)">{{ t("使用最快") }}</Button>
        </div>
        <div class="proxy-node-list grid gap-2 md:grid-cols-3">
          <button
            v-for="node in visibleGroupNodes(group)"
            :key="`${group.name}-${node}`"
            class="proxy-node grid min-h-12 gap-1 rounded-[var(--mn-radius-md)] px-4 py-3 text-left text-sm"
            :aria-pressed="node === group.now"
            type="button"
            :disabled="node === group.now || isRunning('proxy-groups-select')"
            @click="requestSelect(group, node)"
          >
            <span class="proxy-node-name break-words">{{ proxyDisplayName(node) }}</span>
            <span v-if="node === group.now" class="proxy-node-selected mt-1 text-xs">{{ t("已选择") }}</span>
            <span v-if="groupDelays.get(group.name)?.find((entry) => entry.node === node)" class="proxy-node-delay mt-1 text-xs text-[var(--mn-ink-muted)]">
              {{ sanitizeNodeText(groupDelays.get(group.name)?.find((entry) => entry.node === node)?.summary || "") }}
              · {{ nodeDelayQualityLabel(groupDelays.get(group.name)?.find((entry) => entry.node === node)?.quality || "failed") }}
            </span>
          </button>
        </div>
        <Button v-if="remainingGroupNodes(group) > 0" class="mt-3 w-full" size="sm" variant="ghost" @click="showMoreNodes(group)">
          {{ t("显示更多节点（还有 {count} 个）", { count: remainingGroupNodes(group) }) }}
        </Button>
      </section>
      <Button v-if="filteredGroups.length > visibleGroups.length" variant="outline" @click="groupLimit += 8">
        {{ t("显示更多组（还有 {count} 组）", { count: filteredGroups.length - visibleGroups.length }) }}
      </Button>
    </div>
    <div v-else-if="snapshot" class="mn-empty py-6" role="status">
      <p>{{ groupQuery.trim() ? t("没有匹配项") : t("暂无可用代理组") }}</p>
      <Button v-if="groupQuery.trim()" class="mt-3" variant="outline" @click="groupQuery = ''">{{ t("清除搜索") }}</Button>
    </div>
    <p v-else-if="isRunning('proxy-groups-refresh')" class="py-4 text-sm text-[var(--mn-ink-muted)]" role="status">{{ t("正在读取代理组…") }}</p>
    <div v-else-if="rawOutput" class="grid gap-2" role="status">
      <p class="text-sm text-[var(--mn-warning)]">{{ t("未能读取代理组，请刷新重试。") }}</p>
      <pre class="max-h-48 overflow-auto rounded-md bg-[var(--mn-carrier-deep)] p-3 text-xs leading-6 text-[var(--mn-ink-soft)] whitespace-pre-wrap">{{ rawOutput }}</pre>
    </div>
    <p class="proxy-groups-help text-xs leading-5 text-[var(--mn-ink-muted)]">{{ t("选择节点后确认切换。当前选择会优先展示。") }}</p>
    </Card>
  </div>
</template>

<style scoped>
.proxy-node { border: 0; background: var(--mn-surface-sunken); color: var(--mn-ink-soft); cursor: pointer; transition: background-color 160ms ease-out; }
.proxy-node[aria-pressed="true"] { background: var(--mn-accent-soft); color: var(--mn-primary-strong); }
.proxy-node[aria-pressed="true"] > span { color: inherit; }
.proxy-node:disabled { cursor: default; }
.proxy-node:disabled:not([aria-pressed="true"]) { opacity: .55; }
.proxy-node:focus-visible { outline: 2px solid var(--mn-focus); outline-offset: 2px; }
@media (hover: hover) { .proxy-node:hover:not(:disabled) { background: var(--mn-carrier-deep); } }
@media (max-width: 640px) {
  .proxy-groups-surface { gap: 20px; padding: 0; border: 0; border-radius: 0; background: transparent; box-shadow: none; }
  .proxy-groups-toolbar { align-items: center; gap: 8px; }
  .proxy-groups-toolbar h3 { font-size: .8125rem; font-weight: 500; color: var(--mn-ink-muted); }
  .proxy-groups-toolbar > div:last-child { flex-wrap: wrap; gap: 4px; }
  .proxy-groups-toolbar :deep(button) { min-height: 44px; padding-inline: 12px; }
  .proxy-groups-search { position: relative; grid-template-columns: minmax(0, 1fr); gap: 8px; }
  .proxy-groups-search > span { text-align: end; font-size: .75rem; font-variant-numeric: tabular-nums; }
  .proxy-groups-list { gap: 32px; }
  .proxy-group { padding-top: 20px; }
  .proxy-group:first-child { padding-top: 0; border-top: 0; }
  .proxy-group-heading { display: grid; gap: 12px; margin-bottom: 16px; }
  .proxy-group-heading h4 { font-size: 1rem; line-height: 1.5; overflow-wrap: anywhere; }
  .proxy-current-choice { display: grid; gap: 6px; margin: 0; padding-inline-start: 14px; border-inline-start: 2px solid var(--mn-ink); }
  .proxy-current-choice > span { font-size: .75rem; line-height: 1.4; }
  .proxy-current-choice > strong { min-width: 0; font-size: 1.0625rem; font-weight: 550; line-height: 1.5; overflow-wrap: anywhere; }
  .proxy-group-tools { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-bottom: 12px; }
  .proxy-group-tools > p { grid-column: 1 / -1; font-size: .75rem; line-height: 1.6; }
  .proxy-group-tools :deep(button) { min-width: 0; min-height: 44px; white-space: normal; overflow-wrap: anywhere; }
  .proxy-node-list { gap: 0; }
  .proxy-node { position: relative; min-width: 0; min-height: 60px; gap: 4px; padding: 14px 42px 14px 12px; border-bottom: 1px solid var(--mn-border); border-radius: 0; background: transparent; }
  .proxy-node::after { content: ""; position: absolute; top: 22px; inset-inline-end: 14px; width: 14px; height: 14px; border: 1px solid var(--mn-ink-faint); border-radius: 50%; }
  .proxy-node[aria-pressed="true"] { border-radius: 12px; border-bottom-color: transparent; background: var(--mn-surface-raised); color: var(--mn-ink); }
  .proxy-node[aria-pressed="true"]::after { border-color: currentColor; background: currentColor; box-shadow: inset 0 0 0 3px var(--mn-surface-raised); }
  .proxy-node-name { min-width: 0; overflow-wrap: anywhere; line-height: 1.6; }
  .proxy-node-selected, .proxy-node-delay { margin-top: 0; line-height: 1.6; }
  .proxy-groups-help { padding-top: 4px; }
}
@media (forced-colors: active) {
  .proxy-node { border: 1px solid ButtonText; }
  .proxy-node[aria-pressed="true"] { outline: 2px solid Highlight; outline-offset: -2px; color: CanvasText; }
}
</style>
