import { decodeMachineData } from "./machineStatus.ts";

export const CONNECTIVITY_TARGET = "https://www.google.com/generate_204";
const STATUSES = ["unknown", "pending", "online", "degraded", "offline", "paused", "stale"] as const;
export type ConnectivityStatus = {
  status: typeof STATUSES[number];
  reason: string;
  warning: boolean;
  checkedAt: number | null;
  nextCheckAt: number | null;
  latencyMs: number | null;
  retryInSeconds: number | null;
  failures: number;
  lastAction: string;
  actionStatus: string;
};

export const connectivityDefaults: ConnectivityStatus = {
  status: "unknown", reason: "unknown", warning: false, checkedAt: null,
  nextCheckAt: null, latencyMs: null, retryInSeconds: null, failures: 0,
  lastAction: "none", actionStatus: "none",
};

function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function parseConnectivity(value: unknown): ConnectivityStatus | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  if (data.target !== CONNECTIVITY_TARGET || data.path !== "mixed_proxy" ||
    typeof data.status !== "string" || !STATUSES.includes(data.status as ConnectivityStatus["status"]) ||
    typeof data.reason !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(data.reason) ||
    typeof data.warning !== "boolean" || !count(data.consecutive_failures) ||
    typeof data.last_action !== "string" || !["none", "repair", "refresh", "restart", "deferred"].includes(data.last_action) ||
    typeof data.action_status !== "string" || !["none", "pending", "ok", "failed", "busy"].includes(data.action_status) ||
    [data.checked_at, data.next_check_at, data.latency_ms, data.retry_in_seconds].some(value => value !== null && !count(value))) return null;
  // A cached success needs a completed HTTPS probe, not merely a live process.
  if (data.status === "online" && (data.http_status !== 204 || !count(data.checked_at) ||
    data.checked_at === 0 || !count(data.latency_ms))) return null;
  const status = data.status as ConnectivityStatus["status"];
  return {
    status, reason: data.reason,
    warning: ["degraded", "offline", "stale"].includes(status) || (status === "pending" && data.consecutive_failures > 0),
    checkedAt: data.checked_at as number | null,
    nextCheckAt: data.next_check_at as number | null,
    latencyMs: data.latency_ms as number | null,
    retryInSeconds: data.retry_in_seconds as number | null,
    failures: data.consecutive_failures, lastAction: data.last_action, actionStatus: data.action_status,
  };
}

export function parseServiceConnectivity(text: string): ConnectivityStatus {
  const data = decodeMachineData(text, "service.status");
  return parseConnectivity(data?.connectivity) ?? { ...connectivityDefaults };
}

export type SupportExport = { path: string; bytes: number };
export function parseSupportExport(text: string): SupportExport | null {
  const data = decodeMachineData(text, "support.export");
  if (!data || typeof data.path !== "string" ||
    !data.path.startsWith("/") || !data.path.endsWith("/MagicNet-diagnostics.txt") ||
    data.path.length > 512 || /[\x00-\x1f\x7f]/.test(data.path) ||
    !count(data.bytes) || data.bytes === 0 || data.bytes > 2 * 1024 * 1024) return null;
  return { path: data.path, bytes: data.bytes };
}
