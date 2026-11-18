<script setup lang="ts">
import { t } from "@/i18n";
import { Activity, ArrowRight, Copy, Stethoscope } from "lucide-vue-next";
import { computed, ref } from "vue";
import Badge from "@/components/ui/Badge.vue";
import Button from "@/components/ui/Button.vue";
import Card from "@/components/ui/Card.vue";
import CardHeading from "@/components/ui/CardHeading.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import StatusDot from "@/components/ui/StatusDot.vue";
import { useMagicNet } from "@/composables/useMagicNet";
import { copyText } from "@/utils";
import {
  dataPlaneFacts,
  firstRunSteps,
  formatAboutOverview,
  pathFlowNodes,
  successChecks,
} from "./aboutOverview";

const emit = defineEmits<{
  (e: "goto-tab", tab: "control" | "subs" | "health"): void;
}>();

const { state } = useMagicNet();
const copied = ref(false);

const facts = computed(dataPlaneFacts);
const steps = computed(firstRunSteps);
const checks = computed(successChecks);
const pathNodes = computed(pathFlowNodes);
const overview = computed(() => formatAboutOverview(facts.value, steps.value, checks.value));

const dataplaneLabel = computed(() => {
  if (state.runtime.singBoxState === "sing-box") return t("sing-box 运行中");
  if (state.runtime.singBoxState === "stopped") return t("已停止");
  return t("状态未知");
});

const dataplaneTone = computed(() => {
  if (state.runtime.singBoxState === "sing-box") return "success" as const;
  if (state.runtime.singBoxState === "stopped") return "warning" as const;
  return "neutral" as const;
});

const statusDotTone = computed(() => {
  if (state.runtime.singBoxState === "sing-box") return "ok" as const;
  if (state.runtime.singBoxState === "stopped") return "stop" as const;
  return "unknown" as const;
});

async function copyOverview(): Promise<void> {
  copied.value = await copyText(overview.value);
  state.notice = copied.value
    ? t("流量路径已复制。")
    : t("剪贴板不可用，未能复制流量路径。");
}
</script>

<template>
  <div class="mn-path-page">
    <PageHeader :title="t('流量路径')">
      <template #actions>
        <Button variant="ghost" @click="copyOverview">
          <Copy :size="17" aria-hidden="true" />{{ copied ? t("已复制说明") : t("复制说明") }}
        </Button>
      </template>
    </PageHeader>

    <Card class="mn-path-board !p-0">
      <div class="mn-path-board__head">
        <Badge :tone="dataplaneTone" class="gap-2">
          <StatusDot :tone="statusDotTone" />
          {{ dataplaneLabel }}
        </Badge>
      </div>
      <ol class="mn-path-flow" :aria-label="t('MagicNet 透明代理数据面路径')">
        <li
          v-for="(node, index) in pathNodes"
          :key="node.code"
          class="mn-path-flow__node"
        >
          <span class="mn-path-flow__index" aria-hidden="true">{{ node.index }}</span>
          <div class="mn-path-flow__body">
            <strong>{{ node.label }}</strong>
          </div>
          <ArrowRight
            v-if="index < pathNodes.length - 1"
            class="mn-path-flow__arrow"
            :size="16"
            aria-hidden="true"
          />
        </li>
      </ol>
      <div class="mn-path-actions">
        <Button variant="secondary" @click="emit('goto-tab', 'subs')">
          <Activity :size="17" aria-hidden="true" />{{ t("去订阅") }} </Button>
        <Button variant="secondary" @click="emit('goto-tab', 'health')">
          <Stethoscope :size="17" aria-hidden="true" />{{ t("去健康检查") }} </Button>
      </div>
    </Card>

    <details class="mn-path-guide mn-disclosure">
      <summary>{{ t("确认运行正常") }}</summary>
      <Card class="mn-path-explanation grid gap-4">
      <CardHeading
        :description="t('检查服务、透明代理和 DNS。')"
      />
      <ol class="mn-path-steps">
        <li
          v-for="(step, index) in steps"
          :key="step.id"
          class="mn-path-step"
        >
          <span class="mn-path-step__index" aria-hidden="true">{{ index + 1 }}</span>
          <div class="mn-path-step__body">
            <strong>{{ step.title }}</strong>
            <p>{{ step.detail }}</p>
          </div>
        </li>
      </ol>
    </Card>
    </details>

    <details class="mn-path-modes mn-disclosure">
      <summary>{{ t("可用的透明模式") }}</summary>
      <Card class="mn-path-explanation grid gap-4">
      <CardHeading
        :description="t('MagicNet 支持 TUN 和 eBPF；切换失败会恢复原来的配置。')"
      />
      <div class="mn-path-facts">
        <article
          v-for="fact in facts"
          :key="fact.code"
          class="mn-path-fact"
        >
          <h3>{{ fact.title }}</h3>
          <p>{{ fact.detail }}</p>
        </article>
      </div>
    </Card>
    </details>


    <details class="mn-disclosure">
      <summary>{{ t('诊断') }}</summary>
      <div class="mn-disclosure__body">
        <ul class="mn-path-checks m-0 list-none p-0">
          <li
            v-for="check in checks"
            :key="check.command"
            class="mn-path-check"
          >
            <div class="mn-path-check__title">
              <code>{{ check.command }}</code>
            </div>
            <p>{{ check.expect }}</p>
          </li>
        </ul>
        <Button variant="outline" @click="emit('goto-tab', 'control')"> {{ t("返回运行总览") }} </Button>
      </div>
    </details>
  </div>
</template>

<style scoped>
.mn-path-page { display: grid; min-width: 0; gap: var(--mn-section-gap); }
.mn-path-board { display: grid; gap: 20px; min-width: 0; overflow: visible; border: 0; background: transparent; box-shadow: none; }
.mn-path-board__head { padding: 0; }
.mn-path-flow { border: 0; }
.mn-path-flow__node { min-height: 52px; padding: 10px 0; border: 0; gap: 12px; }
.mn-path-flow__index { width: 32px; height: 32px; border: 0; border-radius: var(--mn-radius-md); background: var(--mn-surface-sunken); color: var(--mn-ink-muted); font-weight: 500; }
.mn-path-flow__body strong { font-size: 16px; font-weight: 550; line-height: 1.5; }
.mn-path-flow__arrow { transform: rotate(90deg); }
.mn-path-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.mn-path-actions > button { min-width: 0; min-height: 48px; }
.mn-path-explanation { padding-inline: 0; border: 0; border-radius: 0; background: transparent; }
.mn-path-steps { border: 0; }
.mn-path-step { align-items: start; border: 0; padding: 12px 0; }
.mn-path-step__index { border: 0; background: var(--mn-surface-sunken); color: var(--mn-ink-muted); }
.mn-path-step__body p { margin: 6px 0 0; color: var(--mn-ink-muted); font-size: 14px; line-height: 1.7; overflow-wrap: anywhere; }
.mn-path-facts, .mn-path-checks { gap: 16px; }
.mn-path-fact, .mn-path-check { padding: 8px 0; }
</style>
