<script setup lang="ts">
import { Check, X } from "lucide-vue-next";
import { onMounted, onUnmounted, ref, type Component } from "vue";
import { t } from "@/i18n";
import Button from "@/components/ui/Button.vue";
import { useDialogViewport } from "@/composables/useDialogViewport";
import { trapFocusWithin } from "@/lib/focus";

defineProps<{
  workspace: string;
  currentPage: string;
  pages: readonly { key: string; label: string; hint: string; icon: Component }[];
}>();
const emit = defineEmits<{ close: []; select: [page: string] }>();
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
      :aria-label="t('{workspace}分区', { workspace: t(workspace) })"
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
      <nav class="mn-workspace-sheet__pages" :aria-label="t('{workspace}分区', { workspace: t(workspace) })">
        <button
          v-for="page in pages"
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
      </nav>
    </section>
  </div>
</template>

<style scoped>
.mn-workspace-sheet {
  display: flex;
  max-width: 560px;
  max-height: calc(100% - max(12px, env(safe-area-inset-top)));
  flex-direction: column;
  margin-inline: auto;
  overflow: hidden;
  padding-inline: 16px;
}
.mn-workspace-sheet::before { flex: none; }
.mn-sheet-header { flex: none; padding: 0 4px 12px; }
.mn-workspace-sheet__pages {
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
}
.mn-workspace-sheet__pages button {
  display: flex;
  width: 100%;
  min-height: 72px;
  align-items: center;
  gap: 16px;
  padding: 14px 16px;
  border: 0;
  border-radius: var(--mn-radius-md);
  background: transparent;
  color: var(--mn-ink-muted);
  text-align: start;
  cursor: pointer;
}
.mn-workspace-sheet__pages button > svg { flex: none; }
.mn-workspace-sheet__pages button > span { display: grid; min-width: 0; flex: 1; gap: 4px; }
.mn-workspace-sheet__pages strong { color: var(--mn-ink); font-size: 16px; font-weight: 600; }
.mn-workspace-sheet__pages small { font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
.mn-workspace-sheet__pages button[aria-current="page"] { background: var(--mn-accent-soft); color: var(--mn-primary-strong); }
.mn-workspace-sheet__pages button[aria-current="page"] strong { color: inherit; }
.mn-workspace-sheet__pages button:active { background: var(--mn-surface-sunken); }
.mn-workspace-sheet__pages button:focus-visible { outline-offset: -3px; }
@media (forced-colors: active) {
  .mn-workspace-sheet__pages button[aria-current="page"] { outline: 2px solid Highlight; outline-offset: -3px; }
}
</style>
