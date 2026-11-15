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
  <div class="mn-path-page grid gap-4 md:gap-5">
    <PageHeader :title="t('流量路径')">
      <template #actions>
        <Button variant="outline" @click="copyOverview">
          <Copy :size="17" aria-hidden="true" />{{ copied ? t("已复制说明") : t("复制说明") }}
        </Button>
        <Badge :tone="dataplaneTone" class="gap-2">
          <StatusDot :tone="statusDotTone" />
          {{ dataplaneLabel }}
        </Badge>
      </template>
    </PageHeader>

    <Card class="mn-path-board !p-0">
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
    </Card>

    <Card class="grid gap-4 !p-4 md:!p-6">
      <CardHeading
        :title="t('可用的透明模式')"
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

    <Card class="grid gap-4 !p-4 md:!p-6">
      <CardHeading
        :title="t('确认运行正常')"
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
      <div class="flex flex-wrap gap-2">
        <Button variant="secondary" @click="emit('goto-tab', 'subs')">
          <Activity :size="17" aria-hidden="true" />{{ t("去订阅") }} </Button>
        <Button variant="secondary" @click="emit('goto-tab', 'health')">
          <Stethoscope :size="17" aria-hidden="true" />{{ t("去健康检查") }} </Button>
      </div>
    </Card>

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
