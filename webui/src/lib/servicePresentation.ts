import { t } from "@/i18n";
import type { RuntimeState } from "@/types";
import type { ConnectivityStatus } from "@/composables/connectivityStatus";

type ServiceState = "offline" | "stopped" | "unknown" | "unready" | "ready";

/** A process can exist while its network initialization failed or is unknown. */
export function servicePresentation(runtime: Pick<RuntimeState, "singBoxState" | "serviceReady">, connected = true) {
  const state: ServiceState = !connected ? "offline"
    : runtime.singBoxState === "stopped" ? "stopped"
    : runtime.singBoxState !== "sing-box" || runtime.serviceReady === null ? "unknown"
    : runtime.serviceReady === true ? "ready" : "unready";
  return {
    state,
    label: state === "offline" ? t("未连接设备")
      : state === "stopped" ? t("已停止")
      : state === "unknown" ? t("状态待确认")
      : state === "unready" ? t("服务未就绪") : t("运行中"),
    tone: state === "ready" ? "ok" as const
      : state === "stopped" || state === "unready" ? "stop" as const : "unknown" as const,
    routeState: state === "ready" ? "active" : state === "stopped" ? "stopped" : "unknown",
  };
}


/** Keep the shell and overview aligned when a running service loses connectivity. */
export function connectionPresentation(
  runtime: Pick<RuntimeState, "singBoxState" | "serviceReady">,
  connected: boolean,
  connectivity: Pick<ConnectivityStatus, "status" | "warning">,
) {
  const service = servicePresentation(runtime, connected);
  if (connected && runtime.singBoxState === "sing-box" && connectivity.warning) {
    return { ...service, label: t("连接需要处理"), tone: "stop" as const, routeState: "attention",
      description: t("服务仍在运行。打开 Zashboard 切换节点，或检查网络定位原因。") };
  }
  if (service.state === "ready" && connectivity.status === "online") {
    return { ...service, label: t("网络已连接"),
      description: t("代理连接检查通过。你可以直接打开面板管理节点。") };
  }
  return { ...service, description: "" };
}
