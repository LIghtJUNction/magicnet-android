import { t } from "@/i18n";
import type { RuntimeState, SubscriptionState } from "@/types";

type OverviewInput = {
  connected: boolean;
  busy: boolean;
  runtime: Pick<RuntimeState, "singBoxState">;
  subscriptionReadStatus: "idle" | "loading" | "ready" | "error";
  subscriptions: Pick<SubscriptionState, "configuredCount" | "cacheCount" | "sourceMode" | "lastResult" | "updateRunning" | "updateLockOwner">;
};

/** Suggestions never gate startup: a manually supplied core config is also valid. */
export function controlNextStep(input: OverviewInput) {
  if (!input.connected || input.busy || input.runtime.singBoxState !== "stopped") return null;
  if (input.subscriptionReadStatus !== "ready") {
    return {
      action: "refresh" as const,
      title: t("先读取现有订阅"),
      detail: t("确认设备上的来源后，再继续设置。已有输入会保留。"),
      label: t("重新读取订阅状态"),
    };
  }
  const { configuredCount, cacheCount, sourceMode, lastResult, updateRunning, updateLockOwner } = input.subscriptions;
  if (updateRunning || !["none", "stale"].includes(updateLockOwner)) return null;
  if (cacheCount > 0 || (sourceMode === "local" && lastResult === "success")) {
    return {
      action: "start" as const,
      title: t("启动并检查现有配置"),
      detail: t("启动时会校验现有配置，再确认服务与联网状态。"),
      label: t("启动服务"),
    };
  }
  return configuredCount > 0 ? {
    action: "update" as const,
    title: t("来源已保存，准备节点"),
    detail: sourceMode === "local"
      ? t("重新解析已保存的本地订阅文件，再启动服务。")
      : t("更新订阅以下载节点；完成后再启动服务。"),
    label: t("更新订阅"),
  } : {
    action: "subscriptions" as const,
    title: t("添加订阅，开始使用"),
    detail: t("粘贴订阅链接或导入文件。已有自定义配置也可直接启动。"),
    label: t("添加订阅"),
  };
}
