import { readonly, ref } from "vue";
import { t } from "@/i18n";
import { parseZashboardLaunch, type ZashboardLaunchFailure } from "./zashboardLaunch.ts";
import type { SingBoxUiTarget } from "@/types";
import {
  copyText,
  execFailed,
  intentDataQuote,
  isSensitiveExternalUrl,
  redactedCliPreview,
} from "@/utils";

type RuntimeState = {
  api: string;
  singBoxState: string;
};

type MagicNetState = {
  hasKsu: boolean;
  output: string;
  notice: string;
  phase: "idle" | "accepted" | "queued" | "running" | "done" | "error";
  runtime: RuntimeState;
};

export function useExternalLinks(
  state: MagicNetState,
  runShell: (command: string, label: string, quiet?: boolean, previewOverride?: string) => Promise<string>,
  runCli: (args: string, label?: string, quiet?: boolean, previewOverride?: string) => Promise<string>,
) {
  const openingSingBoxUi = ref(false);
  const singBoxUiError = ref("");
  const launchErrors: Record<ZashboardLaunchFailure, string> = {
    invalid_response: "无法读取面板连接信息。刷新状态后重试。",
    api_unavailable: "本地 API 尚未就绪。请先启动服务，或打开诊断检查核心。",
    panel_missing: "Zashboard 文件缺失。请在下方安装或修复本地面板。",
    invalid_address: "面板地址无效。请检查本地 API 配置。",
  };

  function launchFailed(message: string): false {
    singBoxUiError.value = message;
    state.notice = t("Zashboard 暂未打开");
    state.output = t(message);
    state.phase = "error";
    return false;
  }

  async function openExternal(
    url: string,
    label = t("链接"),
    options: { preferBrowser?: boolean } = {}
  ): Promise<boolean> {
    // Only ever hand http(s) to the browser/intent — guards every current and
    // future caller against javascript: or arbitrary intent:// schemes.
    let safeProtocol = false;
    try {
      safeProtocol = /^https?:$/.test(new URL(url).protocol);
    } catch {
      // Unparseable URL stays unsafe.
    }
    const sensitive = isSensitiveExternalUrl(url);
    if (!safeProtocol) {
      state.output = sensitive
        ? t("已拒绝打开非 http(s) 链接；敏感链接未显示。")
        : t("已拒绝打开非 http(s) 链接：\n{p0}", { p0: url });
      state.phase = "error";
      return false;
    }
    if (sensitive) {
      state.output = t("正在打开 {p0}；敏感链接不会被复制或显示。", { p0: t(label) });
    } else {
      const copied = await copyText(url);
      state.output = copied
        ? t("已复制 {p0}，正在打开系统浏览器：\n{p1}", { p0: t(label), p1: url })
        : `${t("剪贴板不可用。")} ${t("正在打开 {p0}", { p0: t(label) })}\n${url}`;
    }
    if (!state.hasKsu) {
      window.open(url, "_blank", "noopener,noreferrer");
      state.phase = "done";
      return true;
    }
    const escaped = intentDataQuote(url);
    const browserFlag = options.preferBrowser === false ? "" : "-p com.android.chrome ";
    const command = `am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE ${browserFlag}-d ${escaped} >/dev/null 2>&1 || am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d ${escaped}`;
    if (!sensitive) {
      return !execFailed(await runShell(command, t("打开 {p0}", { p0: t(label) })));
    }
    const result = await runShell(
      command,
      t("打开 {p0}", { p0: t(label) }),
      true,
      redactedCliPreview("open external [filtered-url]"),
    );
    if (execFailed(result)) {
      state.phase = "error";
      state.notice = t("打开失败：{p0}", { p0: t(label) });
      state.output = t("打开 {p0} 失败；敏感链接未显示。", { p0: t(label) });
      return false;
    }
    state.phase = "done";
    state.notice = t("已打开：{p0}", { p0: t(label) });
    state.output = t("已打开 {p0}；敏感链接未复制或显示。", { p0: t(label) });
    return true;
  }

  async function openSingBoxUi(target: SingBoxUiTarget): Promise<boolean> {
    if (openingSingBoxUi.value) return false;
    singBoxUiError.value = "";
    if (!state.hasKsu) return launchFailed("请在模块管理器中打开 MagicNet，再进入 Zashboard。");
    openingSingBoxUi.value = true;
    state.notice = t("正在连接 Zashboard");
    try {
      const response = await runCli("--json service status", t("检查 Zashboard"), true,
        redactedCliPreview("--json service status [private-output]"));
      const launch = parseZashboardLaunch(response);
      if (!launch.ok) return launchFailed(launchErrors[launch.reason]);
      if (launch.verifyLocalPanel) {
        const verify = await runCli("webui verify", t("校验本地 Zashboard"), true,
          redactedCliPreview("webui verify [private-output]"));
        const checks = verify.split(/\r?\n/).filter((line) => /^singbox_zashboard=/.test(line.trim()));
        if (execFailed(verify) || checks.length !== 1 || !/^singbox_zashboard=ok(?:\s|$)/.test(checks[0].trim())) {
          return launchFailed(launchErrors.panel_missing);
        }
      }
      if (!await openExternal(launch.url, target)) return launchFailed("系统浏览器未能打开。请稍后重试。");
      return true;
    } catch {
      return launchFailed("无法读取面板连接信息。刷新状态后重试。");
    } finally {
      openingSingBoxUi.value = false;
    }
  }

  return {
    openExternal,
    openSingBoxUi,
    openingSingBoxUi: readonly(openingSingBoxUi),
    singBoxUiError: readonly(singBoxUiError),
  };
}
