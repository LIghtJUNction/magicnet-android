import { decodeMachineData } from "./machineStatus.ts";

export type ZashboardLaunchFailure = "invalid_response" | "api_unavailable" | "panel_missing" | "invalid_address";
export type ZashboardLaunch = { ok: true; url: string; verifyLocalPanel: boolean } | { ok: false; reason: ZashboardLaunchFailure };

/** The local API owns the dashboard address; never reuse a stale UI snapshot. */
export function parseZashboardLaunch(text: string): ZashboardLaunch {
  const data = decodeMachineData(text, "service.status");
  const api = data?.api;
  if (!api || typeof api !== "object" || Array.isArray(api)) return { ok: false, reason: "invalid_response" };
  const { ready, url, webui, webui_ready } = api as Record<string, unknown>;
  if (typeof ready !== "boolean" ||
    (webui_ready !== undefined && typeof webui_ready !== "boolean")) return { ok: false, reason: "invalid_response" };
  if (!ready) return { ok: false, reason: "api_unavailable" };
  if (webui_ready === false) return { ok: false, reason: "panel_missing" };
  if (typeof url !== "string" || typeof webui !== "string" || !url || !webui ||
    url.length > 2048 || webui.length > 2048) return { ok: false, reason: "invalid_address" };
  try {
    const origin = new URL(url);
    const panel = new URL(webui);
    const loopback = origin.hostname === "[::1]" || origin.hostname === "localhost" ||
      /^127(?:\.[0-9]{1,3}){3}$/.test(origin.hostname);
    if (!loopback || !/^https?:$/.test(origin.protocol) || origin.port === "0" ||
      origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash ||
      panel.origin !== origin.origin || panel.username || panel.password ||
      panel.pathname !== "/ui/" || panel.search) return { ok: false, reason: "invalid_address" };
    if (panel.hash) {
      if (!panel.hash.startsWith("#/setup?")) return { ok: false, reason: "invalid_address" };
      const setup = new URLSearchParams(panel.hash.slice("#/setup?".length));
      const host = origin.hostname.replace(/^\[|\]$/g, "");
      const port = origin.port || (origin.protocol === "https:" ? "443" : "80");
      if (setup.get("hostname") !== host || setup.get("port") !== port ||
        [...setup.keys()].some((key) => !["hostname", "port"].includes(key)) ||
        setup.getAll("hostname").length !== 1 || setup.getAll("port").length !== 1) {
        return { ok: false, reason: "invalid_address" };
      }
    }
    return { ok: true, url: panel.href, verifyLocalPanel: webui_ready === undefined };
  } catch {
    return { ok: false, reason: "invalid_address" };
  }
}
