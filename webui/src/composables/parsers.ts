import { t } from "@/i18n";
import { MODULE_DIR, SING_BOX_UI } from "../constants.ts";
import type {
  AppPolicy,
  BlocklistState,
  ConfigValidationState,
  DnsState,
  HealthItem,
  McpState,
  PackageInfo,
  RouteRuleSummary,
  RuntimeState,
  SubscriptionState,
  TransparentMode,
  WarpState,
  WifiPolicyState,
} from "../types.ts";

export type {
  SubscriptionState,
  McpState,
  ConfigValidationState,
  RouteRuleSummary,
};

export const subscriptionDefaults: SubscriptionState = {
  singBox: "",
  singBoxUrls: [],
  sourceUsage: [],
  userAgent: "",
  filters: [],
  configuredCount: 0,
  sourceMode: "url",
  updateRunning: false,
  updateLockOwner: "none",
  lastPhase: "never",
  lastResult: "never",
  lastAttemptEpoch: 0,
  lastSuccessEpoch: 0,
  lastConfiguredCount: 0,
  lastSourceCount: 0,
  lastImportedCount: 0,
  lastSkippedCount: 0,
  lastGenerationId: "none",
  lastReason: "none",
  cacheCount: 0,
  cacheProvenanceCount: 0,
  cacheSource: "unknown",
  scheduleIntervalHours: "off",
  scheduleEnabled: false,
  scheduleRunning: false,
  scheduleOwner: "none",
  scheduleOwnerValid: true,
  refreshEventCount: 0,
  refreshErrorCount: 0,
};

export type NetworkSnapshotSummary = {
  interfaces: number;
  ipRules: number;
  routes: number;
  natRules: number;
};

export type ConnectionTarget = {
  id: string;
  label: string;
  source: string;
  network: string;
  inbound: string;
  rule: string;
  rulePayload: string;
  chain: string;
  process: string;
  detail: string;
  upload: number;
  download: number;
  totalBytes: number;
};

export type ConnectionBucket = {
  name: string;
  query: string;
  count: number;
  bytes: number;
};

export type ConnectionFlowSummary = {
  proxied: number;
  direct: number;
  blocked: number;
  unknown: number;
};

export type ConnectionSnapshot = {
  /** Raw connection count as reported by sing-box, before dedup/filtering. */
  count: number;
  uploadTotal: number;
  downloadTotal: number;
  connections: ConnectionTarget[];
};

export const runtimeDefaults: RuntimeState = {
  singBoxState: "unknown",
  singBox: "unknown",
  singBoxRssKib: null,
  serviceReady: null,
  transparentDataplaneReady: null,
  transparentLocalReady: null,
  transparentSharedReady: null,
  fswatch: "unknown",
  transparentMode: "unknown",
  transparentEffectiveMode: "unknown",
  transparentCapability: "unknown",
  transparentLocalCgroup: "unknown",
  transparentSharedTc: "unknown",
  transparentSharedInterfaces: [],
  transparentSharedInterfaceCount: null,
  transparentRecentError: "",
  transparentTransition: "unknown",
  api: "",
  webui: SING_BOX_UI,
  subPath: `${MODULE_DIR}/.config/sing-box/subscription.url`,
};

export const blockDefaults: BlocklistState = {
  enabled: true,
  community: true,
  url: "https://raw.githubusercontent.com/LIghtJUNction/MagicNet/main/src/MagicNet/.config/magicnet/community-ban.yaml",
  manual: [],
  communityRules: [],
  communityDomains: [],
  allowRules: [],
  newDomain: "",
};

export const mcpDefaults: McpState = {
  enabled: false,
  bind: "127.0.0.1",
  port: "8766",
  pid: "stopped",
  url: "http://127.0.0.1:8766/mcp",
  secretSet: false,
  portOwner: "",
};

function isMcpIpv4Literal(value: string): boolean {
  const octets = value.split(".");
  return (
    octets.length === 4 &&
    octets.every(
      (octet) => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255,
    )
  );
}

function isMcpIpv6Literal(value: string): boolean {
  if (!value.includes(":") || !/^[0-9a-f:.]+$/i.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

/** Match the backend's bare-IP-literal MCP bind contract. */
export function isMcpIpLiteral(value: string): boolean {
  const bind = value.trim();
  return isMcpIpv4Literal(bind) || isMcpIpv6Literal(bind);
}

export function isValidMcpPort(value: string): boolean {
  const port = value.trim();
  const portNumber = Number(port);
  return (
    /^\d+$/.test(port) &&
    Number.isInteger(portNumber) &&
    portNumber >= 1 &&
    portNumber <= 65535
  );
}

/** Render a device endpoint without producing an ambiguous IPv6 host:port. */
export function formatMcpHostPort(bind: string, port: string): string {
  const host = bind.trim();
  const normalizedPort = port.trim();
  return isMcpIpv6Literal(host)
    ? `[${host}]:${normalizedPort}`
    : `${host}:${normalizedPort}`;
}

export function formatMcpUrl(bind: string, port: string): string {
  return `http://${formatMcpHostPort(bind, port)}/mcp`;
}

export const dnsDefaults: DnsState = {
  profile: "default",
  primary: "doh-cloudflare",
  secondary: "",
  transport: "default",
};

export const warpDefaults: WarpState = {
  enabled: false,
  configured: false,
  tag: "warp",
  endpoint: "",
  addresses: 0,
  allowedIps: 0,
  importText: "",
  routeDomain: "",
};

export const wifiPolicyDefaults: WifiPolicyState = {
  observed: false,
  enabled: false,
  policyMode: "blacklist",
  intervalSeconds: 5,
  supervisor: "stopped",
  connected: false,
  ssid: "",
  bssid: "",
  matched: false,
  desiredMode: "rule",
  currentMode: "unavailable",
  ssids: [],
  bssids: [],
};

export function normalizeTransparentMode(
  value: string,
): TransparentMode | null {
  const mode = value.trim().toLowerCase();
  return mode === "tun" || mode === "ebpf" ? mode : null;
}

export function parseHealth(text: string): HealthItem[] {
  return text
    .split(/\r?\n/)
    .map((line) => {
      const match = line
        .trim()
        .match(/^\[(ok|warn|fail|info)\]\s+([^:]+):?\s*(.*)$/i);
      if (!match) return null;
      return {
        status: match[1].toLowerCase() as HealthItem["status"],
        key: match[2].trim(),
        detail: match[3].trim(),
      };
    })
    .filter((item): item is HealthItem => Boolean(item));
}

export function parseApps(text: string): AppPolicy {
  const policy: AppPolicy = { mode: "blacklist", proxy: [], direct: [], bypass: [] };
  readSections(text, policy, {
    "proxy apps:": "proxy", "direct apps:": "direct", "bypass apps:": "bypass",
  }, (line) => {
    if (!line.startsWith("mode=")) return false;
    policy.mode = line.includes("whitelist") ? "whitelist" : "blacklist";
    return true;
  });
  return policy;
}

export function parsePackageCatalog(value: unknown): PackageInfo[] | null {
  if (!value || typeof value !== "object" || !("packages" in value) || !Array.isArray(value.packages) || value.packages.length > 4096) return null;
  const result: PackageInfo[] = [];
  for (const item of value.packages) {
    if (!item || typeof item !== "object" || !("packageName" in item) || !("appLabel" in item) || typeof item.packageName !== "string" || typeof item.appLabel !== "string" || !/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$/.test(item.packageName)) return null;
    result.push({ packageName: item.packageName, appLabel: item.appLabel, versionName: "", versionCode: 0, isSystem: false, uid: 0 });
  }
  return result.sort((a,b) => a.appLabel.localeCompare(b.appLabel));
}

export function parsePackages(text: string): PackageInfo[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) =>
      /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$/.test(line),
    )
    .map((packageName) => ({
      packageName,
      versionName: "",
      versionCode: 0,
      appLabel: packageName,
      isSystem: false,
      uid: 0,
    }));
}

export function parseNetworkSnapshotSummary(
  text: string,
): NetworkSnapshotSummary {
  const lines = text.split(/\r?\n/).map((line) => line.trim());
  return {
    interfaces: countSectionLines(lines, "[interfaces]", "[routes]"),
    ipRules: countSectionLines(lines, "ip rule:", "ip route:"),
    routes: countSectionLines(lines, "ip route:", "[forwarding]"),
    natRules: countSectionLines(lines, "[forwarding]", undefined),
  };
}

export function parseConfigValidation(
  text: string,
): Pick<ConfigValidationState, "status" | "summary"> {
  const trimmed = text.trim();
  if (!trimmed)
    return { status: "error", summary: t("命令没有返回校验结果。") };
  if (/\[info\]\s+Saved and validated/i.test(trimmed)) {
    return {
      status: "ok",
      summary: firstUsefulLine(trimmed) || t("配置已通过校验并保存。"),
    };
  }
  if (
    /config validation failed|validator missing|config target must/i.test(
      trimmed,
    )
  ) {
    return { status: "error", summary: configValidationFailureDetail(trimmed) };
  }
  return {
    status: trimmed.includes("[error]") ? "error" : "ok",
    summary: firstUsefulLine(trimmed) || trimmed.slice(0, 160),
  };
}

function configValidationFailureDetail(text: string): string {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("command:"));
  return (
    lines.find(
      (line) =>
        /(?:fatal|no such file|not found|permission denied|timed out|validator missing)/i.test(
          line,
        ) && !/^config validation failed$/i.test(line),
    ) ||
    lines.find((line) => !/^config validation failed$/i.test(line)) ||
    t("配置校验失败。")
  );
}

export function parseRouteRuleSummary(text: string): RouteRuleSummary {
  const summary: RouteRuleSummary = { proxy: [], direct: [], block: [], warp: [] };
  readSections(text, summary, {
    "proxy domain suffixes:": "proxy", "direct domain suffixes:": "direct",
    "block domain suffixes:": "block", "warp domain suffixes:": "warp",
  }, undefined, true);
  return summary;
}

/** The text compatibility formats share section traversal, not field semantics. */
function readSections<K extends string>(
  text: string,
  target: Record<K, string[]>,
  headings: Record<string, K>,
  consume: (line: string) => boolean = () => false,
  foldHeadings = false,
): void {
  let section: K | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || consume(line)) continue;
    const heading = foldHeadings ? line.toLowerCase() : line;
    if (Object.hasOwn(headings, heading)) section = headings[heading];
    else if (section !== undefined && !(foldHeadings && line.endsWith(":"))) target[section].push(line);
  }
}

export function parseConnectionSnapshot(
  text: string,
): ConnectionSnapshot | null {
  try {
    const root = JSON.parse(text) as Record<string, unknown>;
    const rawConnections = Array.isArray(root.connections)
      ? root.connections
      : null;
    if (!rawConnections) return null;
    const unique = new Map<string, ConnectionTarget>();
    for (const value of rawConnections) {
      const target = parseConnectionTarget(value);
      if (target && !unique.has(target.id)) unique.set(target.id, target);
    }
    const connections = [...unique.values()].sort((left, right) => right.totalBytes - left.totalBytes);
    return {
      count: rawConnections.length,
      uploadTotal: safeNumber(root.uploadTotal),
      downloadTotal: safeNumber(root.downloadTotal),
      connections,
    };
  } catch {
    return null;
  }
}

export function connectionMatchesQuery(
  target: ConnectionTarget,
  query: string,
): boolean {
  const terms = query
    .split(/\s+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (!terms.length) return true;
  const haystack = [
    target.label,
    target.process,
    target.source,
    target.inbound,
    target.network,
    target.rule,
    target.rulePayload,
    target.chain,
    target.detail,
  ]
    .join(" ")
    .toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

export function connectionBuckets(
  connections: ConnectionTarget[],
  kind: "rule" | "chain" | "process",
): ConnectionBucket[] {
  const buckets: Record<string, ConnectionBucket> = Object.create(null);
  for (const target of connections) {
    const name = bucketName(target, kind);
    if (!name) continue;
    const bucket = buckets[name] ??= {
      name, query: kind === "chain" ? name.replace(/ > /g, " ") : name, count: 0, bytes: 0,
    };
    bucket.count += 1;
    bucket.bytes += target.totalBytes;
  }
  return Object.values(buckets)
    .sort((left, right) => right.bytes - left.bytes || right.count - left.count)
    .slice(0, 4);
}

export function connectionFlowSummary(
  connections: ConnectionTarget[],
): ConnectionFlowSummary {
  return connections.reduce<ConnectionFlowSummary>(
    (acc, target) => {
      const flow = connectionFlow(target);
      acc[flow] += 1;
      return acc;
    },
    { proxied: 0, direct: 0, blocked: 0, unknown: 0 },
  );
}

function connectionFlow(target: ConnectionTarget): keyof ConnectionFlowSummary {
  const text = [
    target.chain,
    target.rule,
    target.rulePayload,
    target.inbound,
    target.detail,
  ]
    .join(" ")
    .toLowerCase();
  if (/\b(block|reject)\b/.test(text)) return "blocked";
  if (/\b(direct|bypass)\b/.test(text)) return "direct";
  if (
    target.chain ||
    /\b(proxy|select|warp|wireguard|trojan|vmess|vless|shadowsocks|hysteria)\b/.test(
      text,
    )
  )
    return "proxied";
  return "unknown";
}

function bucketName(
  target: ConnectionTarget,
  kind: "rule" | "chain" | "process",
): string {
  if (kind === "rule")
    return [target.rule, target.rulePayload].filter(Boolean).join(" ");
  if (kind === "process") return target.process || target.inbound;
  return target.chain || target.network;
}

function parseConnectionTarget(value: unknown): ConnectionTarget | null {
  if (!value || typeof value !== "object") return null;
  const item = value as Record<string, unknown>;
  const metadata = (
    item.metadata && typeof item.metadata === "object" ? item.metadata : {}
  ) as Record<string, unknown>;
  const id = stringValue(item.id);
  const host = stringValue(metadata.host);
  const destination = stringValue(metadata.destinationIP);
  const port = String(metadata.destinationPort ?? "");
  const target = host || destination;
  if (!id || !target) return null;
  const label = !port || port === "0" ? target : `${target}:${port}`;
  const chain = Array.isArray(item.chains)
    ? item.chains.map(stringValue).filter(Boolean).join(" > ")
    : "";
  const network = stringValue(metadata.network);
  const source = sourceLabel(metadata);
  const inbound =
    stringValue(item.inbound) ||
    stringValue(metadata.inbound) ||
    stringValue(metadata.type);
  const rule = stringValue(item.rule);
  const rulePayload = stringValue(item.rulePayload);
  const process = processLabel(metadata);
  const upload = safeNumber(item.upload);
  const download = safeNumber(item.download);
  return {
    id,
    label,
    source,
    network,
    inbound,
    rule,
    rulePayload,
    chain,
    process,
    detail:
      [process, source, inbound, network, rule, rulePayload, chain]
        .filter(Boolean)
        .join(" · ") || "direct",
    upload,
    download,
    totalBytes: upload + download,
  };
}

function sourceLabel(metadata: Record<string, unknown>): string {
  const ip = stringValue(metadata.sourceIP) || stringValue(metadata.source);
  const port = String(metadata.sourcePort ?? "");
  if (!ip) return "";
  return port && port !== "0" ? `${ip}:${port}` : ip;
}

function processLabel(metadata: Record<string, unknown>): string {
  const packageName = stringValue(metadata.processPackageName);
  if (packageName) return packageName;
  const processName = stringValue(metadata.processName);
  if (processName) return processName;
  const path = stringValue(metadata.processPath);
  return path.split("/").filter(Boolean).at(-1) || "";
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function safeNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, value)
    : 0;
}

function firstUsefulLine(text: string): string {
  return (
    text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line && !line.startsWith("command:")) || ""
  );
}

function countSectionLines(
  lines: string[],
  start: string,
  end: string | undefined,
): number {
  const startIndex = lines.findIndex(
    (line) => line.toLowerCase() === start.toLowerCase(),
  );
  if (startIndex < 0) return 0;
  const relativeEnd = end
    ? lines
        .slice(startIndex + 1)
        .findIndex((line) => line.toLowerCase() === end.toLowerCase())
    : -1;
  const endIndex =
    relativeEnd >= 0 ? startIndex + 1 + relativeEnd : lines.length;
  return lines
    .slice(startIndex + 1, endIndex)
    .filter(
      (line) =>
        line &&
        !line.startsWith("[") &&
        line !== "ip rule:" &&
        line !== "ip route:",
    ).length;
}

export function parseBlock(
  text: string,
  previous: BlocklistState,
): BlocklistState {
  const next: BlocklistState = {
    ...previous,
    manual: [],
    communityRules: [],
    communityDomains: [],
    allowRules: [],
  };
  readSections(text, next, {
    "manual domain suffixes:": "manual", "community rules:": "communityRules",
    "community domain suffixes:": "communityDomains", "local allow rules:": "allowRules",
  }, (line) => {
    if (line.startsWith("enabled=")) next.enabled = line.slice(8) !== "0";
    else if (line.startsWith("community=")) next.community = line.slice(10) !== "0";
    else if (line.startsWith("url=")) next.url = line.slice(4);
    else return false;
    return true;
  });
  return next;
}

export function parseMcp(text: string, previous: McpState): McpState {
  const next = { ...previous, portOwner: "" };
  readFields(text, {
    enabled: (value) => { next.enabled = value !== "0"; },
    bind: (value) => { next.bind = value; },
    port: (value) => { next.port = value; },
    pid: (value) => { next.pid = value; },
    secret_set: (value) => { next.secretSet = value === "1"; },
    port_owner: (value) => { next.portOwner = value; },
  });
  next.url = formatMcpUrl(next.bind, next.port);
  return next;
}

export function parseWarp(text: string, previous: WarpState): WarpState {
  const next = { ...previous };
  readFields(text, {
    enabled: (value) => { next.enabled = value === "1"; },
    configured: (value) => { next.configured = value === "1"; },
    tag: (value) => { next.tag = value || "warp"; },
    endpoint: (value) => { next.endpoint = value; },
    addresses: (value) => { next.addresses = Number(value) || 0; },
    allowed_ips: (value) => { next.allowedIps = Number(value) || 0; },
  });
  return next;
}

function readFields(text: string, fields: Record<string, (value: string) => void>): void {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const separator = line.indexOf("=");
    if (separator < 0) continue;
    const name = line.slice(0, separator);
    if (Object.hasOwn(fields, name)) fields[name](line.slice(separator + 1));
  }
}
