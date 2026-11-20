<script setup lang="ts">
import { t } from "@/i18n";
import { CheckCircle2, Copy, DownloadCloud, ExternalLink, Github, RefreshCw, Terminal, PanelsTopLeft, ArrowUpRight, ChevronDown } from "lucide-vue-next";
import { computed, ref, watch } from "vue";
import Badge from "@/components/ui/Badge.vue";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import Input from "@/components/ui/Input.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import Textarea from "@/components/ui/Textarea.vue";
import { useActionLock } from "@/composables/useActionLock";
import { useMagicNet } from "@/composables/useMagicNet";
import { copyText, redactSensitiveText, redactedCliPreview } from "@/utils";
import ToolActionConfirmCard from "./ToolActionConfirmCard.vue";
import type { PendingToolAction } from "./toolActions";
import { buildWebuiInstallPlan, formatWebuiInstallPlanReport, webuiInstallPlanTone, type WebuiInstallPlan } from "./webuiInstallPlan";
import { buildWebuiPanelInsight, webuiInsightTone, type WebuiVerifyCheck } from "./webuiPanelInsights";

const { state, runCli, startPrivateBackgroundCli, openExternal, openSingBoxUi, openingSingBoxUi, singBoxUiError, shellQuote, REPO } = useMagicNet();
const emit = defineEmits<{ (e: "goto-tab", tab: "control" | "health"): void }>();
const maintenance = ref<HTMLDetailsElement | null>(null);
function showMaintenance(): void {
  if (maintenance.value) {
    maintenance.value.open = true;
    maintenance.value.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}
const { isRunning, withAction } = useActionLock();
const status = ref("");
const verifyOutput = ref("");
const reportCopied = ref(false);
const commandCopied = ref(false);
const planCopied = ref(false);
const pendingWebuiAction = ref<PendingToolAction | null>(null);
const panel = ref({
  name: "zashboard",
  url: "https://github.com/Zephyruso/zashboard/releases/download/v3.30.0/dist-no-fonts.zip",
  sha256: "ec794e7c4daf4c839ecbc0a1292fdaf7bc7a6e3e4a4ce284db2b32379145c278",
  metadata: ""
});
const panelPresets = [
  {
    label: "zashboard no-fonts",
    name: "zashboard",
    url: "https://github.com/Zephyruso/zashboard/releases/download/v3.30.0/dist-no-fonts.zip",
    sha256: "ec794e7c4daf4c839ecbc0a1292fdaf7bc7a6e3e4a4ce284db2b32379145c278",
    note: "MagicNet 默认本地面板，包体更小，适合设备侧后台下载。"
  },
  {
    label: "zashboard full",
    name: "zashboard",
    url: "https://github.com/Zephyruso/zashboard/releases/download/v3.30.0/dist.zip",
    sha256: "1f91c014e61e768240a86ad0a9bd565b247ec5a0e26b125fb5d19076682905b7",
    note: "完整字体包体积更大；下载包会在安装前校验 SHA-256。"
  }
];

const verifyChecks = computed(() => parseVerifyChecks(verifyOutput.value));
const verifyFailed = computed(() => verifyOutput.value.toLowerCase().includes("failed") || verifyChecks.value.some((item) => item.status !== "ok"));
const panelInsight = computed(() => buildWebuiPanelInsight(verifyChecks.value, verifyOutput.value));
const installArgs = computed(() => {
  const url = panel.value.url.trim();
  const sha256 = panel.value.sha256.trim();
  const name = panel.value.name.trim() || "custom";
  return url && sha256 ? `webui install-local ${shellQuote(url)} ${shellQuote(sha256)} ${shellQuote(name)}` : "";
});
const installPlan = computed(() => buildWebuiInstallPlan(
  panel.value.url,
  panel.value.sha256,
  redactSensitiveText(panel.value.name.trim() || "custom"),
));
const panelWarnings = computed(() => buildPanelWarnings(panel.value.url, panel.value.name, panel.value.sha256, installPlan.value));

async function refreshWebui(): Promise<void> {
  await withAction("webui-status", async () => {
    const rawStatus = await runCli(
      "webui status",
      t("读取 WebUI 配置"),
      true,
      redactedCliPreview("webui status [private-output]"),
    );
    status.value = redactSensitiveText(rawStatus);
    state.output = status.value;
  });
}

async function verifyWebui(): Promise<void> {
  await withAction("webui-verify", async () => {
    const rawVerifyOutput = await runCli(
      "webui verify",
      t("校验 WebUI 面板"),
      true,
      redactedCliPreview("webui verify [private-output]"),
    );
    const safeVerifyOutput = redactSensitiveText(rawVerifyOutput);
    verifyOutput.value = safeVerifyOutput;
    state.output = safeVerifyOutput;
  });
}

async function copyWebuiReport(): Promise<void> {
  const report = [
    "MagicNet WebUI panel report",
    `created_at=${new Date().toISOString()}`,
    `verify_failed=${verifyFailed.value ? 1 : 0}`,
    `insight_status=${panelInsight.value.status}`,
    `insight_title=${panelInsight.value.title}`,
    `missing=${panelInsight.value.missing.join(",") || "none"}`,
    "",
    "[checks]",
    ...verifyChecks.value.map((check) => `${check.name}=${check.status}${check.path ? ` path=${check.path}` : ""}`),
    "",
    "[status]",
    status.value || "(not loaded)",
    "",
    "[verify]",
    verifyOutput.value || "(not verified)"
  ].join("\n").trim();
  reportCopied.value = await copyText(sanitizeWebuiReport(report));
  state.output = reportCopied.value ? t("WebUI 面板报告已复制。") : t("剪贴板不可用，WebUI 面板报告未复制。");
}

async function copyInstallCommand(): Promise<void> {
  if (!installArgs.value) {
    state.output = t("请先填写本地面板下载 URL。");
    return;
  }
  const safeCommand = installPlan.value.safeCommand || "webui install-local [filtered-url] [sha256] custom";
  commandCopied.value = await copyText(safeCommand);
  state.output = commandCopied.value ? t("WebUI 脱敏安装命令已复制。") : t("剪贴板不可用，WebUI 脱敏安装命令未复制。");
}

async function copyInstallPlan(): Promise<void> {
  planCopied.value = await copyText(formatWebuiInstallPlanReport(installPlan.value));
  state.output = planCopied.value ? t("WebUI 安装计划已复制。") : t("剪贴板不可用，安装计划未复制。");
}

function sanitizeWebuiReport(text: string): string {
  return redactSensitiveText(text);
}

function cancelWebuiAction(): void {
  pendingWebuiAction.value = null;
}

async function confirmWebuiAction(): Promise<void> {
  const action = pendingWebuiAction.value;
  if (!action) return;
  try {
    await action.run();
  } finally {
    pendingWebuiAction.value = null;
  }
}

async function runInstallLocal(command: string, preview: string): Promise<void> {
  await withAction("webui-install", async () => {
    await startPrivateBackgroundCli(
      command,
      t("安装本地 WebUI 面板"),
      `su -M -c ${shellQuote(preview)}`,
      preview,
    );
  });
}

function installLocal(): void {
  const url = panel.value.url.trim();
  const name = panel.value.name.trim() || "custom";
  if (!/^https?:\/\/\S+$/i.test(url)) {
    state.output = t("本地面板下载 URL 必须是 http(s) 链接。");
    return;
  }
  if (panelWarnings.value.some((item) => item.tone === "danger")) {
    state.output = t("请先修正本地面板配置中的错误项。");
    return;
  }
  const command = installArgs.value;
  const displayName = redactSensitiveText(name);
  const safeCommand = installPlan.value.safeCommand || "webui install-local [filtered-url] [sha256] custom";
  pendingWebuiAction.value = {
    key: "webui-install",
    title: t("后台下载并安装 WebUI 面板"),
    detail: t("会下载 {value} 面板压缩包并写入模块本地 WebUI 资源。{value2}", { value: displayName, value2: installPlan.value.status === "warning" ? ` ${installPlan.value.detail}` : "" }),
    command: safeCommand,
    run: () => runInstallLocal(command, safeCommand),
  };
}

function applyPanelPreset(item: { name: string; url: string; sha256: string; note: string }): void {
  panel.value = {
    name: item.name,
    url: item.url,
    sha256: item.sha256,
    metadata: t(item.note)
  };
  commandCopied.value = false;
  planCopied.value = false;
}

function issueUrl(): string {
  const issueName = redactSensitiveText(panel.value.name.trim() || "custom");
  const issueMetadata = redactSensitiveText(panel.value.metadata.trim()) || "(empty)";
  const body = [
    "## WebUI panel adaptation request",
    "",
    `Name: ${issueName}`,
    `Kind: ${panel.value.url ? "local-download" : "online"}`,
    "",
    "## Metadata",
    issueMetadata,
    "",
    t("请审核后决定是否内置该面板。")
  ].join("\n");
  return `${REPO}/issues/new?${new URLSearchParams({ title: t("申请适配 WebUI 面板：{value}", { value: issueName }), body }).toString()}`;
}

function parseVerifyChecks(text: string): WebuiVerifyCheck[] {
  return text.split(/\r?\n/).map((line) => {
    const match = line.match(/^([^=\s]+)=(ok|missing)(?:\s+path=(.*))?$/);
    if (!match) return null;
    return {
      name: match[1].replace(/_/g, " "),
      status: match[2] === "ok" ? "ok" : "missing",
      path: match[3] || ""
    };
  }).filter((item): item is WebuiVerifyCheck => Boolean(item));
}

function buildPanelWarnings(url: string, name: string, sha256: string, plan: WebuiInstallPlan): Array<{ text: string; tone: "success" | "warning" | "danger" }> {
  const trimmedUrl = url.trim();
  const trimmedName = name.trim();
  const warnings: Array<{ text: string; tone: "success" | "warning" | "danger" }> = [];
  if (!trimmedName) warnings.push({ text: t("未填写面板名，CLI 会使用 custom。"), tone: "warning" });
  if (!trimmedUrl) return [{ text: t("未填写下载 URL，无法安装。"), tone: "danger" }, ...warnings];
  if (!/^https?:\/\/\S+$/i.test(trimmedUrl)) warnings.push({ text: t("URL 必须是 http(s) 链接且不能包含空白字符。"), tone: "danger" });
  // The http/zip/credential policy lives in buildWebuiInstallPlan — surface its
  // verdict here instead of re-implementing the checks per page.
  else if (plan.status === "danger") warnings.push({ text: plan.detail, tone: "danger" });
  if (plan.status === "warning") warnings.push({ text: plan.detail, tone: "warning" });
  if (!/^[a-fA-F0-9]{64}$/.test(sha256.trim())) warnings.push({ text: t("必须提供 64 位 SHA-256 校验值。"), tone: "danger" });
  if (!warnings.length) warnings.push({ text: t("安装命令可执行，下载和解压结果以后台任务日志为准。"), tone: "success" });
  return warnings;
}

watch(() => [panel.value.name, panel.value.url, panel.value.sha256], () => {
  commandCopied.value = false;
  planCopied.value = false;
});

</script>

<template>
  <div class="mn-webui-page">
    <PageHeader :overline="t('面板')" title="Zashboard">
      <Button variant="ghost" @click="showMaintenance">{{ t("安装与修复") }}<ChevronDown :size="16" /></Button>
    </PageHeader>

    <section class="mn-panel-launch" :aria-label="t('Zashboard 快捷入口')">
      <div>
        <p class="mn-panel-launch-title">{{ t("节点与连接，一键直达。") }}</p>
        <p class="mn-panel-launch-description">{{ t("打开设备上的 Zashboard，自动填入本地 API 地址。") }}</p>
      </div>
        <div class="mn-panel-observation" :class="webuiInsightTone(panelInsight.status)">
          <div class="mn-panel-observation-heading">
            <p class="text-sm font-semibold">{{ panelInsight.title }}</p>
          <Badge v-if="verifyOutput" :tone="verifyFailed ? 'danger' : 'success'">{{ verifyFailed ? t("校验失败") : t("校验通过") }}</Badge>
          </div>
          <p class="mt-1 break-words text-sm leading-6 opacity-80">{{ panelInsight.detail }}</p>
        </div>
      <div class="mn-panel-launch-actions">
        <Button :disabled="!state.hasKsu" :loading="openingSingBoxUi" @click="openSingBoxUi('zashboard')"><PanelsTopLeft :size="18" />{{ openingSingBoxUi ? t("正在连接 Zashboard") : t("打开 Zashboard") }}<ArrowUpRight :size="17" /></Button>
        <p>{{ t(state.hasKsu ? "本地运行，无需另外输入地址" : "在模块管理器中打开后可使用") }}</p>
        <div class="mn-panel-read-actions">
        <Button variant="outline" :loading="isRunning('webui-status')" @click="refreshWebui"><RefreshCw :size="17" />{{ t("读取") }}</Button>
        <Button variant="outline" :loading="isRunning('webui-verify')" @click="verifyWebui"><CheckCircle2 :size="17" />{{ t("校验面板") }}</Button>
        </div>
      </div>
      <div v-if="singBoxUiError" class="mn-panel-launch-error" role="alert">
        <p>{{ t(singBoxUiError) }}</p>
        <div class="flex flex-wrap gap-2">
          <Button variant="secondary" @click="showMaintenance">{{ t("安装与修复") }}</Button>
          <Button variant="ghost" @click="emit('goto-tab', 'control')">{{ t("返回概览") }}</Button>
        </div>
      </div>
    </section>

    <details ref="maintenance" class="mn-panel-maintenance">
      <summary>{{ t("安装与修复") }}<ChevronDown :size="18" aria-hidden="true" /></summary>
      <p class="mb-5 text-sm leading-6 text-[var(--mn-ink-muted)]">{{ t("已安装面板可直接打开。仅在文件缺失或需要更新时使用以下工具。") }}</p>
        <p class="text-sm leading-6 text-[var(--mn-ink-muted)]">{{ t("sing-box 默认使用本地 zashboard。面板下载会在后台执行，避免大文件下载被前台超时中断。") }}</p>

    <ToolActionConfirmCard
      v-if="pendingWebuiAction"
      :action="pendingWebuiAction"
      :loading="isRunning(pendingWebuiAction.key)"
      @cancel="cancelWebuiAction"
      @confirm="confirmWebuiAction"
    />

    <div class="mn-panel-install-workspace">
      <Card class="mn-panel-install grid gap-4">
        <h3 class="text-base font-semibold">{{ t("本地面板") }}</h3>
        <div class="flex flex-wrap gap-2">
          <Button v-for="item in panelPresets" :key="item.url" variant="outline" @click="applyPanelPreset(item)">
            {{ item.label }}
          </Button>
        </div>
        <Input v-model="panel.name" :placeholder="t('面板名字，例如 zashboard')" spellcheck="false" />
        <Input v-model="panel.url" placeholder="https://example.com/panel.zip" spellcheck="false" />
        <Input v-model="panel.sha256" :placeholder="t('面板包 SHA-256（64 位十六进制）')" spellcheck="false" />
        <Textarea v-model="panel.metadata" class="min-h-28" :placeholder="t('面板元数据、说明、仓库链接、适配注意事项')" spellcheck="false" />
          <div class="mn-panel-warnings flex flex-wrap gap-2">
            <Badge v-for="item in panelWarnings" :key="item.text" :tone="item.tone">{{ item.text }}</Badge>
          </div>
        <details class="mn-panel-install-details mn-disclosure">
          <summary>{{ t("安装前检查") }}</summary>
          <div class="mn-disclosure__body">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <Button variant="outline" :disabled="!installArgs" @click="copyInstallCommand"><Terminal :size="16" />{{ commandCopied ? t("已复制脱敏命令") : t("复制脱敏命令") }}</Button>
          </div>
          <div class="mn-panel-plan text-sm leading-6" :class="webuiInstallPlanTone(installPlan.status)">
            <p class="font-medium">{{ installPlan.title }}</p>
            <p class="mt-1 text-xs opacity-80">{{ installPlan.detail }}</p>
            <p class="mt-2 text-xs opacity-80">
              {{ installPlan.host || t("无主机") }} · {{ installPlan.archive || t("未知包类型") }} · {{ t("查询参数：{value}", { value: installPlan.hasQuery ? t("有") : t("无") }) }}
            </p>
          </div>
          <code class="break-all rounded-md bg-[var(--mn-carrier-deep)] px-3 py-2 text-xs leading-6 text-[var(--mn-ink-soft)]">{{ installPlan.safeCommand || "webui install-local [filtered-url] [sha256] [name]" }}</code>
          </div>
        </details>
        <Button variant="outline" :disabled="!panel.url.trim()" @click="copyInstallPlan"><Copy :size="17" />{{ planCopied ? t("已复制计划") : t("复制安装计划") }}</Button>
        <Button :disabled="panelWarnings.some((item) => item.tone === 'danger')" :loading="isRunning('webui-install')" @click="installLocal"><DownloadCloud :size="17" />{{ t("后台下载并安装") }}</Button>
      </Card>


    </div>
    </details>

    <details class="mn-panel-report mn-disclosure">
      <summary>{{ t("当前状态") }}</summary>
      <div class="mn-disclosure__body">
        <div class="mn-panel-report-actions">
        <Button variant="outline" :disabled="!status && !verifyOutput" :loading="isRunning('webui-copy-report')" @click="withAction('webui-copy-report', copyWebuiReport)"><Copy :size="17" />{{ reportCopied ? t("已复制报告") : t("复制报告") }}</Button>
        <Button variant="outline" @click="openExternal(issueUrl(), t('WebUI 适配 Issue'))"><Github :size="17" />{{ t("申请适配") }}</Button>
        </div>
        <Button variant="outline" @click="openExternal(REPO, 'MagicNet GitHub')"><ExternalLink :size="17" />{{ t("打开项目仓库") }}</Button>
        <div v-if="verifyChecks.length" class="grid gap-2">
          <div v-for="check in verifyChecks" :key="check.name" class="mn-panel-check grid gap-2">
            <div class="flex items-center justify-between gap-2">
              <span class="text-sm font-medium text-[var(--mn-ink)]">{{ check.name }}</span>
              <Badge :tone="check.status === 'ok' ? 'success' : 'danger'">{{ check.status === "ok" ? t("通过") : check.status === "missing" ? t("缺失") : t("未知") }}</Badge>
            </div>
            <p v-if="check.path" class="break-all text-xs text-[var(--mn-ink-muted)]">{{ check.path }}</p>
          </div>
        </div>
        <pre class="max-h-80 overflow-auto rounded-md bg-[var(--mn-carrier-deep)] p-3 text-xs leading-6 text-[var(--mn-ink-soft)] whitespace-pre-wrap">{{ status || t("点击读取查看 webui status。") }}</pre>
        <pre v-if="verifyOutput" class="max-h-48 overflow-auto rounded-md bg-[var(--mn-carrier-deep)] p-3 text-xs leading-6 text-[var(--mn-ink-soft)] whitespace-pre-wrap">{{ verifyOutput }}</pre>
      </div>
    </details>
  </div>
</template>

<style scoped>
.mn-webui-page { display: grid; min-width: 0; gap: var(--mn-section-gap); }
.mn-panel-launch { display: grid; min-width: 0; gap: 20px; padding: 24px 20px; border-radius: var(--mn-radius-xl); background: var(--mn-surface-sunken); }
.mn-panel-launch-title { margin: 0; color: var(--mn-ink); font-size: 24px; font-weight: 550; letter-spacing: -.025em; line-height: 1.45; }
.mn-panel-launch-description { margin: 8px 0 0; color: var(--mn-ink-muted); font-size: 14px; line-height: 1.7; }
.mn-panel-observation { display: grid; gap: 6px; min-width: 0; border: 0; border-radius: 0; padding: 0; background: transparent; }
.mn-panel-observation-heading { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
.mn-panel-observation-heading > p { margin: 0; }
.mn-panel-launch-actions > button { width: 100%; min-height: 52px; }
.mn-panel-launch-actions > p { margin: 10px 0 0; color: var(--mn-ink-muted); font-size: 12px; line-height: 1.6; text-align: center; }
.mn-panel-read-actions, .mn-panel-report-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; min-width: 0; }
.mn-panel-read-actions { margin-top: 16px; }
.mn-panel-read-actions > button { min-width: 0; border-color: transparent; background: transparent; }
.mn-panel-launch-error { color: var(--mn-danger); font-size: 14px; }
.mn-panel-launch-error p { margin: 0 0 12px; overflow-wrap: anywhere; }
.mn-panel-maintenance { min-width: 0; border-bottom: 1px solid var(--mn-border); padding-bottom: 12px; }
.mn-panel-maintenance > summary { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 64px; list-style: none; cursor: pointer; font-size: 15px; font-weight: 550; }
.mn-panel-maintenance > summary::-webkit-details-marker { display: none; }
.mn-panel-maintenance[open] > summary > svg { transform: rotate(180deg); }
.mn-panel-maintenance > summary:focus-visible { outline: 2px solid var(--mn-focus); outline-offset: 3px; border-radius: var(--mn-radius-sm); }
.mn-panel-install-workspace { min-width: 0; padding-top: 24px; }
.mn-panel-install { border: 0; border-radius: 0; padding: 0 0 12px; background: transparent; }
.mn-panel-warnings { min-width: 0; }
.mn-panel-warnings :deep(span) { max-width: 100%; white-space: normal; overflow-wrap: anywhere; }
.mn-panel-plan { min-width: 0; border: 0; padding: 0; background: transparent; }
.mn-panel-check { min-width: 0; padding: 12px 0; border-bottom: 1px solid var(--mn-border); }
.mn-panel-report pre { min-width: 0; overflow-wrap: anywhere; }
</style>
