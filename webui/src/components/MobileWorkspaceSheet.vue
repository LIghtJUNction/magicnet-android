<script setup lang="ts">
import { Check, X } from "lucide-vue-next";
import { computed, onMounted, onUnmounted, ref, type Component } from "vue";
import { t } from "@/i18n";
import Button from "@/components/ui/Button.vue";
import { useDialogViewport } from "@/composables/useDialogViewport";
import { trapFocusWithin } from "@/lib/focus";

const props = defineProps<{
  workspace: string;
  currentPage: string;
  pages: readonly { key: string; label: string; hint: string; icon: Component; workspace?: string }[];
}>();
const emit = defineEmits<{ close: []; select: [page: string] }>();
const groups = computed(() => {
  const sections = [
    { key: "run", label: "运行" },
    { key: "route", label: "路由" },
    { key: "configure", label: "配置" },
    { key: "diagnose", label: "诊断" },
    { key: "", label: "全部页面" },
  ];
  return sections
    .map((section) => ({ ...section, pages: props.pages.filter((page) => (page.workspace || "") === section.key) }))
    .filter((section) => section.pages.length > 0);
});
const dialog = ref<HTMLElement | null>(null);
const { viewportStyle } = useDialogViewport();
let previousBodyOverflow = "";

function selectPage(page: string): void {
  emit("close");
  emit("select", page);
}

onMounted(() => {
  previousBodyOverflow = document.body.style.overflow;
  document.body.style.overflow = "hidden";
  dialog.value?.querySelector<HTMLElement>("[data-dialog-initial-focus]")?.focus();
});
onUnmounted(() => {
  document.body.style.overflow = previousBodyOverflow;
});
</script>

<template>
  <div class="mn-sheet-layer" :style="viewportStyle">
    <button class="mn-overlay" type="button" tabindex="-1" :aria-label="t('关闭页面导航')" @click="emit('close')" />
    <section
      ref="dialog"
      class="mn-utility-sheet mn-workspace-sheet"
      role="dialog"
      aria-modal="true"
      :aria-label="t(workspace)"
      tabindex="-1"
      @keydown="trapFocusWithin($event, dialog)"
      @keydown.esc.prevent.stop="emit('close')"
    >
      <header class="mn-sheet-header">
        <h2>{{ t(workspace) }}</h2>
        <Button data-dialog-initial-focus variant="ghost" size="icon" :aria-label="t('关闭页面导航')" @click="emit('close')">
          <X :size="20" aria-hidden="true" />
        </Button>
      </header>
      <nav class="mn-workspace-sheet__pages" :aria-label="t(workspace)">
        <section v-for="group in groups" :key="group.key" class="mn-workspace-sheet__group" :aria-label="t(group.label)">
          <h3>{{ t(group.label) }}</h3>
        <button
          v-for="page in group.pages"
          :key="page.key"
          type="button"
          :data-page="page.key"
          :aria-current="page.key === currentPage ? 'page' : undefined"
          @click="selectPage(page.key)"
        >
          <component :is="page.icon" :size="21" aria-hidden="true" />
          <span><strong>{{ t(page.label) }}</strong><small>{{ t(page.hint) }}</small></span>
          <Check v-if="page.key === currentPage" :size="19" aria-hidden="true" />
        </button>
        </section>
      </nav>
    </section>
  </div>
</template>

<style scoped>
.mn-workspace-sheet {
  inset: 0 auto 0 0;
  display: flex;
  width: min(370px, calc(100% - 24px));
  max-width: none;
  max-height: 100%;
  flex-direction: column;
  margin: 0;
  overflow: hidden;
  padding: max(20px, env(safe-area-inset-top)) 12px max(16px, env(safe-area-inset-bottom));
  border-radius: 0 20px 20px 0;
}
.mn-workspace-sheet::before { display: none; }
.mn-sheet-header { flex: none; padding: 0 8px 18px; }
.mn-sheet-header h2 { font-size: 20px; }
.mn-workspace-sheet__pages { min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding-bottom: 16px; }
.mn-workspace-sheet__group + .mn-workspace-sheet__group { margin-top: 20px; }
.mn-workspace-sheet__group > h3 { margin: 0; padding: 8px 16px; color: var(--mn-ink-muted); font-size: 11px; font-weight: 500; }
.mn-workspace-sheet__pages button {
  display: flex;
  width: 100%;
  min-height: 68px;
  align-items: center;
  gap: 14px;
  padding: 12px 16px;
  border: 0;
  border-radius: var(--mn-radius-md);
  background: transparent;
  color: var(--mn-ink-muted);
  text-align: start;
  cursor: pointer;
}
.mn-workspace-sheet__pages button > svg { flex: none; }
.mn-workspace-sheet__pages button > span { display: grid; min-width: 0; flex: 1; gap: 4px; }
.mn-workspace-sheet__pages strong { color: var(--mn-ink); font-size: 14px; font-weight: 550; }
.mn-workspace-sheet__pages small { font-size: 12px; line-height: 1.5; overflow-wrap: anywhere; }
.mn-workspace-sheet__pages button[aria-current="page"] { background: var(--mn-accent-soft); color: var(--mn-primary-strong); }
.mn-workspace-sheet__pages button[aria-current="page"] strong { color: inherit; }
.mn-workspace-sheet__pages button:active { background: var(--mn-surface-sunken); }
.mn-workspace-sheet__pages button:focus-visible { outline-offset: -3px; }
@media (forced-colors: active) {
  .mn-workspace-sheet__pages button[aria-current="page"] { outline: 2px solid Highlight; outline-offset: -3px; }
}
</style>
