<script setup lang="ts">
import { computed } from "vue";
import { t } from "@/i18n";
import type { RuntimeState } from "@/types";
import { buildConstellation, type StarState } from "./constellationPath";

const props = defineProps<{ runtime: RuntimeState; hasDevice: boolean }>();

const model = computed(() => buildConstellation(props.runtime, props.hasDevice));
const summaryText = computed(() => ({
  flowing: t("流量经数据面进入 sing-box，按规则选择出口。实际联网请在诊断中确认。"),
  stopped: t("sing-box 已停止，MagicNet 当前没有接管流量。"),
  partial: t("路径部分就绪；虚线断开的位置就是需要检查的环节。"),
  unknown: t("状态未确认，路径不会按已接管显示。"),
}[model.value.summary]));

function stateText(state: StarState): string {
  return state === "ok" ? t("已就绪") : state === "off" ? t("未就绪") : t("未确认");
}
</script>

<template>
  <figure class="mn-constellation" :data-summary="model.summary">
    <ol class="mn-constellation__path" :aria-label="t('流量路径')">
      <li
        v-for="(star, index) in model.stars"
        :key="star.key"
        class="mn-constellation__star"
        :data-state="star.state"
        :data-edge="index > 0 ? model.edges[index - 1] : undefined"
      >
        <span class="mn-constellation__mark" aria-hidden="true" />
        <strong>{{ t(star.label) }}</strong>
        <span class="mn-constellation__state">{{ stateText(star.state) }}</span>
        <small>{{ t(star.detail) }}</small>
      </li>
    </ol>
    <figcaption>{{ summaryText }}</figcaption>
  </figure>
</template>

<style scoped>
.mn-constellation {
  margin: 0;
  padding: 24px 0 4px;
}

.mn-constellation__path {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
  padding: 0;
  list-style: none;
}

.mn-constellation__star {
  --point-size: 10px;
  --line: var(--mn-border-strong);
  position: relative;
  display: grid;
  min-width: 0;
  justify-items: center;
  align-content: start;
  gap: 2px;
  padding: 0 2px;
  text-align: center;
}

/* Connect adjacent state markers without suggesting live packet activity. */
.mn-constellation__star + .mn-constellation__star::before {
  position: absolute;
  z-index: 0;
  top: calc(var(--point-size) / 2);
  right: calc(50% + var(--point-size) / 2 + 8px);
  left: calc(-50% + var(--point-size) / 2 + 8px);
  border-top: 1px dashed var(--line);
  content: "";
}

.mn-constellation__star[data-edge="flowing"]::before {
  --line: var(--mn-primary);
  border-top-style: solid;
}

.mn-constellation__star[data-edge="idle"]::before {
  --line: color-mix(in srgb, var(--mn-ink-faint) 45%, transparent);
  border-top-style: dotted;
}

.mn-constellation__mark {
  position: relative;
  z-index: 1;
  width: var(--point-size);
  height: var(--point-size);
  margin-bottom: 10px;
  border: 1px dashed var(--mn-ink-muted);
  border-radius: 50%;
  background: var(--mn-ivory);
}

.mn-constellation__star[data-state="ok"] .mn-constellation__mark {
  border-style: solid;
  border-color: var(--mn-success);
  background: var(--mn-success);
}

.mn-constellation__star[data-state="off"] .mn-constellation__mark {
  border-style: solid;
  border-color: var(--mn-ink-muted);
}

.mn-constellation__star strong {
  max-width: 100%;
  overflow-wrap: anywhere;
  color: var(--mn-ink);
  font-size: 13px;
  font-weight: 650;
  line-height: 1.25;
}

.mn-constellation__star small {
  max-width: 100%;
  overflow-wrap: anywhere;
  color: var(--mn-ink-muted);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.35;
}

.mn-constellation__state {
  color: var(--mn-ink-muted);
  font-size: 12px;
  line-height: 1.5;
}

.mn-constellation__star[data-state="off"] strong,
.mn-constellation__star[data-state="unknown"] strong {
  color: var(--mn-ink-soft);
}

figcaption {
  margin: 16px 0 0;
  color: var(--mn-ink-muted);
  font-size: 12.5px;
  line-height: 1.6;
}

@media (min-width: 640px) {
  .mn-constellation__star strong {
    font-size: 14px;
  }

  .mn-constellation__star small {
    font-size: 12px;
  }
}

@media (forced-colors: active) {
  .mn-constellation__star + .mn-constellation__star::before {
    border-color: CanvasText;
  }

  .mn-constellation__mark {
    border-color: CanvasText;
    background: Canvas;
  }

  .mn-constellation__star[data-state="ok"] .mn-constellation__mark {
    border-color: Highlight;
    background: Highlight;
  }
}
</style>
