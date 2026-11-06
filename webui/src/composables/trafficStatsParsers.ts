import { t } from "@/i18n";
export type TrafficSample = {
  up: number;
  down: number;
  timestampMillis: number;
  source: "json" | "kv";
  sourceKey: string;
};

export type TrafficStatsSummary = {
  latest: TrafficSample | null;
  averageUp: number;
  averageDown: number;
  peakUp: number;
  peakDown: number;
  peakTotal: number;
  peakTotalTimestampMillis: number | null;
  sampleCount: number;
  windowMillis: number;
};

export type TrafficAlertState = {
  level: "idle" | "ok" | "warning" | "danger";
  message: string;
  latestTotal: number;
  thresholdBytesPerSecond: number;
  sustainedSamples: number;
};

export type TrafficSamplingHealthReport = {
  level: "idle" | "ok" | "warning" | "danger";
  label: string;
  detail: string;
  latestAgeSeconds: number | null;
  sampleCount: number;
  consecutiveFailures: number;
};

export function parseTrafficSample(text: string, timestampMillis = Date.now()): TrafficSample | null {
  const wholeJson = parseTrafficJson(text, timestampMillis);
  if (wholeJson) return wholeJson;
  const lines = text.split(/\r?\n/);
  let kvLine: string | undefined;
  for (let index = lines.length - 1; index >= 0; index--) {
    const line = lines[index];
    const sample = parseTrafficJson(line, timestampMillis);
    if (sample) return sample;
    if (kvLine === undefined && /\bup\s*=/.test(line) && /\bdown\s*=/.test(line)) kvLine = line;
  }
  if (kvLine) {
    const fields = Object.fromEntries(kvLine.split(/\s+/).map((part) => part.split("=", 2)).filter((pair) => pair.length === 2));
    const pair = trafficPair(fields, "", null);
    return pair ? {
      up: pair.up,
      down: pair.down,
      timestampMillis: pair.timestampMillis ?? timestampMillis,
      source: "kv",
      sourceKey: pair.sourceKey
    } : null;
  }
  return null;
}

export function buildTrafficStatsSummary(samples: TrafficSample[]): TrafficStatsSummary {
  let sumUp = 0, sumDown = 0, peakUp = 0, peakDown = 0, peakTotal = 0;
  let peakTotalTimestampMillis: number | null = null;
  for (const sample of samples) {
    sumUp += sample.up;
    sumDown += sample.down;
    peakUp = Math.max(peakUp, sample.up);
    peakDown = Math.max(peakDown, sample.down);
    const total = sample.up + sample.down;
    if (total > peakTotal || (total === peakTotal && peakTotalTimestampMillis === null)) {
      peakTotalTimestampMillis = sample.timestampMillis;
    }
    peakTotal = Math.max(peakTotal, total);
  }
  return {
    latest: samples.at(-1) || null,
    averageUp: samples.length ? sumUp / samples.length : 0,
    averageDown: samples.length ? sumDown / samples.length : 0,
    peakUp,
    peakDown,
    peakTotal,
    peakTotalTimestampMillis: Number.isNaN(peakTotal) ? null : peakTotalTimestampMillis,
    sampleCount: samples.length,
    windowMillis: samples.length >= 2 ? Math.max(0, samples[samples.length - 1].timestampMillis - samples[0].timestampMillis) : 0
  };
}

export function evaluateTrafficAlert(samples: TrafficSample[], thresholdMiBPerSecond: number): TrafficAlertState {
  const thresholdBytesPerSecond = Math.max(0, thresholdMiBPerSecond) * 1024 * 1024;
  const latest = samples.at(-1);
  const latestTotal = latest ? latest.up + latest.down : 0;
  const result: TrafficAlertState = {
    level: "idle", message: t("未设置告警阈值。"), latestTotal,
    thresholdBytesPerSecond, sustainedSamples: 0,
  };
  if (!thresholdBytesPerSecond) return result;
  if (!latest) return { ...result, message: t("等待真实流量样本。") };
  let consecutive = 0;
  for (let index = samples.length - 1; index >= 0; index--) {
    if (samples[index].up + samples[index].down < thresholdBytesPerSecond) break;
    consecutive++;
  }
  if (consecutive >= 3) return {
    ...result, level: "danger", sustainedSamples: consecutive,
    message: t("连续 {consecutive} 个样本超过阈值。", { consecutive }),
  };
  return latestTotal >= thresholdBytesPerSecond
    ? { ...result, level: "warning", sustainedSamples: consecutive, message: t("最近一个样本超过阈值。") }
    : { ...result, level: "ok", message: t("当前流量低于阈值。") };
}

export function formatTrafficStatsReport(
  samples: TrafficSample[],
  alert?: TrafficAlertState,
  samplingHealth?: TrafficSamplingHealthReport
): string {
  const summary = buildTrafficStatsSummary(samples);
  const latest = summary.latest;
  const previous = samples.at(-2);
  const latestTotal = latest ? latest.up + latest.down : 0;
  const previousTotal = previous ? previous.up + previous.down : 0;
  const latestDelta = latest && previous ? latestTotal - previousTotal : 0;
  const latestTrend = latest && previous ? latestDelta > 0 ? "up" : latestDelta < 0 ? "down" : "flat" : "none";
  const latestIntervalMillis = latest && previous ? latest.timestampMillis - previous.timestampMillis : 0;
  const reportWindow = Math.min(samples.length, 12);
  const windowSamples = samples.slice(-reportWindow);
  const windowPeak = windowSamples.length ? Math.max(...windowSamples.map((sample) => sample.up + sample.down)) : 0;
  return [
    "MagicNet traffic stats",
    `samples=${summary.sampleCount}`,
    `assumed_unit=bytes_per_second`,
    `parse_source=${summary.latest?.source || "none"}`,
    `parse_source_key=${summary.latest?.sourceKey || "none"}`,
    `window_seconds=${Math.round(summary.windowMillis / 1000)}`,
    `window_samples=${reportWindow}`,
    `window_peak_total_bytes_per_second=${Math.round(windowPeak)}`,
    `latest_total_bytes_per_second=${Math.round(latestTotal)}`,
    `latest_total_delta_bytes_per_second=${Math.round(latestDelta)}`,
    `latest_interval_millis=${Math.max(0, Math.round(latestIntervalMillis))}`,
    `latest_trend=${latestTrend}`,
    `peak_total_bytes_per_second=${Math.round(summary.peakTotal)}`,
    `peak_total_time=${summary.peakTotalTimestampMillis ? new Date(summary.peakTotalTimestampMillis).toISOString() : "none"}`,
    `latest_up=${Math.round(summary.latest?.up || 0)}`,
    `latest_down=${Math.round(summary.latest?.down || 0)}`,
    `average_up=${Math.round(summary.averageUp)}`,
    `average_down=${Math.round(summary.averageDown)}`,
    `peak_up=${Math.round(summary.peakUp)}`,
    `peak_down=${Math.round(summary.peakDown)}`,
    `alert_level=${alert?.level || "none"}`,
    `alert_threshold_bytes_per_second=${Math.round(alert?.thresholdBytesPerSecond || 0)}`,
    `alert_sustained_samples=${alert?.sustainedSamples || 0}`,
    `sampling_health_level=${samplingHealth?.level || "none"}`,
    `sampling_health_label=${samplingHealth?.label || "none"}`,
    `sampling_health_detail=${samplingHealth?.detail || "none"}`,
    `sampling_latest_age_seconds=${samplingHealth?.latestAgeSeconds ?? "none"}`,
    `sampling_consecutive_failures=${samplingHealth?.consecutiveFailures || 0}`,
    "",
    "index,timestamp,source,up_bytes_per_second,down_bytes_per_second",
    ...samples.map((sample, index) => `${index + 1},${new Date(sample.timestampMillis).toISOString()},${sample.source},${Math.round(sample.up)},${Math.round(sample.down)}`)
  ].join("\n").trim();
}

function parseTrafficJson(text: string, timestampMillis: number): TrafficSample | null {
  try {
    const json = JSON.parse(text);
    const pair = findTrafficPair(json);
    return pair ? { ...pair, timestampMillis: pair.timestampMillis ?? timestampMillis, source: "json" } : null;
  } catch {
    return null;
  }
}

type TrafficPair = {
  up: number;
  down: number;
  sourceKey: string;
  timestampMillis: number | null;
};

function findTrafficPair(value: unknown): TrafficPair | null {
  return findTrafficPairAt(value, "", 0, new Set(), null);
}

function findTrafficPairAt(
  value: unknown,
  path: string,
  depth: number,
  seen: Set<unknown>,
  inheritedTimestampMillis: number | null
): TrafficPair | null {
  if (depth > 6 || seen.has(value) || value === null) return null;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      const pair = findTrafficPairAt(item, path, depth + 1, seen, inheritedTimestampMillis);
      if (pair) return pair;
    }
    return null;
  }
  if (!isRecord(value)) return null;

  const fallbackTimestamp = parseTrafficTimestamp(value) ?? inheritedTimestampMillis;

  const direct = trafficPair(value, path, fallbackTimestamp);
  if (direct) return direct;

  const preferredKeys = ["traffic", "stats", "connections", "data", "result", "payload"];
  for (const key of preferredKeys) {
    if (!(key in value)) continue;
    const pair = findTrafficPairAt(value[key], joinPath(path, key), depth + 1, seen, fallbackTimestamp);
    if (pair) return pair;
  }

  for (const [key, child] of Object.entries(value)) {
    if (preferredKeys.includes(key)) continue;
    const pair = findTrafficPairAt(child, joinPath(path, key), depth + 1, seen, fallbackTimestamp);
    if (pair) return pair;
  }
  return null;
}

function trafficPair(fields: Record<string, unknown>, path = "", fallbackTimestampMillis: number | null = null): TrafficPair | null {
  const pairs = [
    ["up", "down"],
    ["upload", "download"],
    ["uploadSpeed", "downloadSpeed"],
    ["upload_speed", "download_speed"]
  ];
  for (const [upKey, downKey] of pairs) {
    const up = numberValue(fields[upKey]);
    const down = numberValue(fields[downKey]);
    if (up !== null && down !== null) {
      return {
        up,
        down,
        timestampMillis: parseTrafficTimestamp(fields) ?? fallbackTimestampMillis,
        sourceKey: `${path ? `${path}.` : ""}${upKey}/${downKey}`
      };
    }
  }
  return null;
}

function parseTrafficTimestamp(value: unknown): number | null {
  if (!isRecord(value)) return null;
  const candidates = [
    "timestamp",
    "timestampMillis",
    "timestamp_ms",
    "time",
    "timeMillis",
    "time_ms",
    "time_unix",
    "timeUnix",
    "createdAt",
    "created_at",
    "updatedAt",
    "updated_at",
    "created"
  ];
  for (const key of candidates) {
    if (!(key in value)) continue;
    const parsed = parseTrafficTimestampValue(value[key]);
    if (parsed !== null) return parsed;
  }
  return null;
}

function parseTrafficTimestampValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return normalizeTimestamp(value);
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text) return null;
  const numeric = Number(text);
  if (Number.isFinite(numeric)) return normalizeTimestamp(numeric);
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeTimestamp(timestamp: number): number | null {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return null;
  return timestamp < 1e12 ? Math.round(timestamp * 1000) : Math.round(timestamp);
}

function joinPath(parent: string, key: string): string {
  return parent ? `${parent}.${key}` : key;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(0, value);
  if (typeof value === "string") {
    const parsed = value.match(/([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?b)?(?:\/s)?/i);
    if (!parsed) return null;
    const amount = Number(parsed[1]);
    if (!Number.isFinite(amount)) return null;
    const unit = (parsed[2] || "").toLowerCase();
    const scale = unit === "kb" ? 1024 : unit === "mb" ? 1024 ** 2 : unit === "gb" ? 1024 ** 3 : unit === "tb" ? 1024 ** 4 : 1;
    return Math.max(0, amount * scale);
  }
  return null;
}

