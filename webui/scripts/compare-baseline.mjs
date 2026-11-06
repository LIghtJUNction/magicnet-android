#!/usr/bin/env node
// Usage: node --experimental-strip-types --import ./test-register.mjs scripts/compare-baseline.mjs BASELINE_WEBUI
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const here = fileURLToPath(new URL("..", import.meta.url));
const modules = ["parsers", "trafficStatsParsers", "nodeDelayParsers"];
const load = async (root, name) => import(pathToFileURL(resolve(root, "src/composables", `${name}.ts`)));

function connections(count) {
  return JSON.stringify({ uploadTotal: 4700, downloadTotal: 8100, connections: Array.from({ length: count }, (_, index) => ({
    id: `id-${index % Math.max(1, Math.floor(count * 0.8))}`,
    metadata: { host: `host-${index}.example`, destinationPort: 443, processName: `app-${index % 7}`,
      sourceIP: "192.0.2.5", sourcePort: 1000 + index, network: index % 2 ? "tcp" : "udp" },
    rule: ["direct", "proxy", "block", "__proto__", "1", "2"][index % 6],
    rulePayload: index % 3 ? "example" : "", chains: [`group-${index % 4}`, `node-${index % 11}`],
    upload: index * 17, download: index * 31,
  })) });
}

if (process.argv[2] === "--worker") {
  const parser = await load(process.argv[3], "parsers");
  const payload = connections(6000);
  for (let round = 0; round < 3; round++) parser.parseConnectionSnapshot(payload);
  globalThis.gc?.();
  const timings = [];
  for (let round = 0; round < 11; round++) {
    const started = performance.now();
    assert.equal(parser.parseConnectionSnapshot(payload).connections.length, 4800);
    timings.push(performance.now() - started);
  }
  timings.sort((a, b) => a - b);
  process.stdout.write(JSON.stringify({ rows: 6000, runs: timings.length,
    median_ms: timings[Math.floor(timings.length / 2)], max_rss_kib: process.resourceUsage().maxRSS }));
  process.exit(0);
}

const baselineRoot = process.argv[2];
if (!baselineRoot) throw new Error("Supply the immutable baseline WebUI directory");
const baseline = Object.fromEntries(await Promise.all(modules.map(async name => [name, await load(baselineRoot, name)])));
const candidate = Object.fromEntries(await Promise.all(modules.map(async name => [name, await load(here, name)])));
let cases = 0;
function compare(module, name, ...args) {
  const before = baseline[module][name](...structuredClone(args));
  const after = candidate[module][name](...structuredClone(args));
  assert.deepStrictEqual(after, before, `${module}.${name}, case ${cases + 1}`);
  cases++;
  return after;
}

const textSeeds = [
  "", "garbage", "__proto__\nconstructor", "enabled=0\r\ncommunity=1\r\nurl=https://example.invalid/a=b",
  "mode=whitelist\nproxy apps:\napp.one\ndirect apps:\napp.two\nbypass apps:\napp.three",
  "manual domain suffixes:\nexample.org\ncommunity rules:\nDOMAIN,example.net\ncommunity domain suffixes:\nexample.com\nlocal allow rules:\nDOMAIN,allowed.example",
  "Proxy Domain Suffixes:\none.example\nDIRECT DOMAIN SUFFIXES:\ntwo.example\nblock domain suffixes:\nthree.example\nwarp domain suffixes:\nfour.example",
  "enabled=\nbind=::1\nport=8766\npid=123\nsecret_set=1\nport_owner=owned\nunknown=x",
  "enabled=1\nconfigured=0\ntag=\nendpoint=example:443\naddresses=2\nallowed_ips=3",
  "[ok] core: ready\n[warn] routes: stale\n[fail] dns: blocked\n[info] probe: pending",
  "[interfaces]\nwlan0\n[/routes]\n[routes]\nip rule:\nrule1\nip route:\nroute1\n[forwarding]\nrule2",
  "[info] Saved and validated\ncommand: save", "config validation failed\nFATAL invalid field",
];
for (let index = 0; index < textSeeds.length; index++) {
  for (const text of [textSeeds[index], `  ${textSeeds[index]}\n`, `${textSeeds[index]}\n${textSeeds[(index + 1) % textSeeds.length]}`]) {
    for (const name of ["parseHealth", "parseApps", "parsePackages", "parseRouteRuleSummary", "parseNetworkSnapshotSummary", "parseConfigValidation"])
      compare("parsers", name, text);
    for (const [name, defaults] of [["parseBlock", "blockDefaults"], ["parseMcp", "mcpDefaults"], ["parseWarp", "warpDefaults"]])
      compare("parsers", name, text, baseline.parsers[defaults]);
  }
}
for (const count of [0, 1, 2, 9, 41, 200, 2000, 6000]) {
  const snapshot = compare("parsers", "parseConnectionSnapshot", connections(count));
  for (const kind of ["rule", "chain", "process"]) compare("parsers", "connectionBuckets", snapshot.connections, kind);
  compare("parsers", "connectionFlowSummary", snapshot.connections);
  for (const row of snapshot.connections.slice(0, 4)) {
    for (const query of ["", "tcp group-1", "APP-1", "example node"]) compare("parsers", "connectionMatchesQuery", row, query);
  }
}
for (const input of ["null", "[]", "{}", "not json", JSON.stringify({ connections: [null, {}, { id: "x", metadata: { host: "example" } }, { id: "x", upload: 999, metadata: { host: "other" } }] })])
  compare("parsers", "parseConnectionSnapshot", input);

for (let count = 0; count <= 64; count++) {
  const samples = Array.from({ length: count }, (_, index) => ({ up: index * 37, down: (index % 9) * 1000,
    timestampMillis: 1700000000000 + index * 1000, source: "json", sourceKey: "up/down" }));
  compare("trafficStatsParsers", "buildTrafficStatsSummary", samples);
  compare("trafficStatsParsers", "formatTrafficStatsReport", samples);
  for (const threshold of [0, 0.001, 1]) compare("trafficStatsParsers", "evaluateTrafficAlert", samples, threshold);
  const text = Array.from({ length: count }, (_, index) => `node-${index % 7}=${index % 4 ? `${index * 19}ms` : "timeout"}`).join("\n");
  const nodes = compare("nodeDelayParsers", "parseNodeTestAll", text);
  compare("nodeDelayParsers", "buildNodeDelayStats", nodes);
  compare("nodeDelayParsers", "formatNodeDelayReport", nodes);
  compare("nodeDelayParsers", "fastestEntry", nodes);
  compare("nodeDelayParsers", "slowestEntry", nodes);
}
for (const text of ["", "up=12 down=43", '{"up":12,"down":43}', '[info] traffic\n{"stats":{"up":"4 kb/s","down":"2 MB/s","time":1700000000}}', '{"up":3,"down":4}\nup=999 down=999', "up=1 down=2\nup=no down=none"])
  compare("trafficStatsParsers", "parseTrafficSample", text, 1700000000000);

function measure(root) {
  const run = spawnSync(process.execPath, ["--expose-gc", "--experimental-strip-types", "--import",
    resolve(here, "test-register.mjs"), fileURLToPath(import.meta.url), "--worker", resolve(root)], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout);
}
console.log(JSON.stringify({ parity_cases: cases, mismatches: 0,
  connection_parse: { baseline: measure(baselineRoot), candidate: measure(here) } }, null, 2));
