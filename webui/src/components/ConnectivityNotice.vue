<script setup lang="ts">
import { computed } from "vue";
import { t } from "@/i18n";
import { statusToneClasses } from "@/lib/statusTone";
import type { ConnectivityStatus } from "@/composables/connectivityStatus";

const props = defineProps<{ snapshot: ConnectivityStatus }>();
const labels = {
  unknown: "Google 连通性尚未确认", pending: "正在检查 Google 连接",
  online: "Google 连接正常", degraded: "⚠️ Google 暂不可达",
  offline: "⚠️ Google 连接失败", paused: "Google 探测已暂停", stale: "⚠️ Google 探测结果已过期",
};
const reasonLabels: Record<string, string> = {
  dns_failed: "域名解析失败", dns: "域名解析失败", dns_failure: "域名解析失败", tls_failed: "TLS 校验失败", tls: "TLS 校验失败", tls_failure: "TLS 校验失败",
  timeout: "连接超时", connect_failed: "代理连接失败", proxy_unavailable: "代理入口不可用",
  no_interface: "没有可用的网络出口", no_default_interface: "没有可用的网络出口",
  http_failed: "目标返回异常状态", http_status: "目标返回异常状态",
  core_stopped: "服务已停止", disabled: "模块已停用", network_offline: "网络出口不可达",
  no_default_route: "没有可用的网络出口", endpoint_specific: "其他探测可用，Google 暂不可达",
  proxy_refused: "代理连接失败", http_error: "目标返回异常状态", module_disabled: "模块已停用",
  upstream_unavailable: "代理上游不可达",
};
const reason = computed(() => reasonLabels[props.snapshot.reason] || "正在检查代理、网络出口和订阅状态。");
const actionLabels: Record<string, string> = {
  repair: "已尝试修复路由与 DNS", refresh: "已尝试更新订阅",
  restart: "已尝试重启内核", deferred: "等待当前操作完成后重试",
};
</script>

<template>
  <section class="grid gap-2 rounded-md px-4 py-3 text-sm" data-testid="connectivity-notice"
    :class="snapshot.warning ? statusToneClasses('warn') : 'text-[var(--mn-ink-soft)]'"
    :role="snapshot.warning ? 'alert' : 'status'" aria-live="polite">
    <p class="font-medium">{{ snapshot.status === 'pending' && snapshot.warning ? t('⚠️ 正在复查 Google 连接') : t(labels[snapshot.status]) }}<span v-if="snapshot.status === 'online' && snapshot.latencyMs !== null" class="ml-2 font-normal tabular-nums">{{ snapshot.latencyMs }} ms</span></p>
    <template v-if="snapshot.warning">
      <p>{{ t(reason) }}</p>
      <p v-if="snapshot.retryInSeconds !== null">{{ t('自动重试间隔逐步延长，约 {seconds} 秒后再次检查。', { seconds: snapshot.retryInSeconds }) }}</p>
      <p v-if="actionLabels[snapshot.lastAction]">{{ t(actionLabels[snapshot.lastAction]) }}<span v-if="snapshot.actionStatus === 'failed'"> · {{ t('本次恢复未成功') }}</span></p>
    </template>
    <p v-else-if="snapshot.status === 'online'" class="text-xs text-[var(--mn-ink-muted)]">{{ t('通过代理检查；正常时每 5 分钟检测一次。') }}</p>
    <slot />
  </section>
</template>
