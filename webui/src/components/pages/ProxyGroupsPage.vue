<script setup lang="ts">
import { t } from "@/i18n";
import PageHeader from "@/components/ui/PageHeader.vue";
import ProxyGroupsPanel from "./ProxyGroupsPanel.vue";
import NodeDelayPanel from "./NodeDelayPanel.vue";
import RoutingEditor from "./RoutingEditor.vue";
</script>

<template>
  <div class="proxy-groups-page grid gap-6">
    <PageHeader :title="t('节点与代理组')" :description="t('为各类流量选择已有出口，或测速后切换节点。')" />
    <section class="proxy-groups-workspace" :aria-label="t('代理组')">
      <ProxyGroupsPanel />
    </section>
    <section class="proxy-routing-workspace" :aria-label="t('分流编辑')">
      <RoutingEditor />
    </section>
    <details class="mn-disclosure proxy-measurement-workspace"><summary>{{ t("节点测速") }}</summary><NodeDelayPanel /></details>
  </div>
</template>

<style scoped>
@media (max-width: 640px) {
  .proxy-groups-page { gap: 28px; min-width: 0; }
  .proxy-groups-workspace, .proxy-routing-workspace { min-width: 0; }
  .proxy-routing-workspace { border-top: 1px solid var(--mn-border); padding-top: 24px; }
  .proxy-measurement-workspace { border-radius: 0; border-inline: 0; background: transparent; }
  .proxy-measurement-workspace > summary { min-height: 56px; padding-inline: 0; }
}
</style>
