import assert from "node:assert/strict";
import test from "node:test";
import { CONNECTIVITY_TARGET, connectivityDefaults, parseConnectivity, parseServiceConnectivity, parseSupportExport } from "./src/composables/connectivityStatus.ts";

const envelope = (command, data) => JSON.stringify({ schema: 1, ok: true, command, data });
const online = { target: CONNECTIVITY_TARGET, path: "mixed_proxy", status: "online", reason: "ok", warning: false,
  checked_at: 1234, next_check_at: 1534, latency_ms: 52, http_status: 204, retry_in_seconds: 300,
  consecutive_failures: 0, last_action: "none", action_status: "none" };

test("successful proxy probes preserve backend TUN warnings across service refresh", () => {
  for (const status of ["missing", "unknown", "stale"]) {
    const data = {...online, path:"selected_proxy", mixed_status:"online", warning:true,
      tun_auto_route:{status, warning:true}};
    const result = parseServiceConnectivity(envelope("service.status", {connectivity:data}));
    assert.equal(result.status, "online");
    assert.equal(result.warning, true, status);
  }
  assert.equal(parseConnectivity(online).warning, false);
});

test("service refresh reads cached connectivity and preserves older-module unknown", () => {
  assert.equal(parseServiceConnectivity(envelope("service.status", { connectivity: online })).status, "online");
  for (const text of [envelope("service.status", {}), envelope("connectivity.status", online), "not JSON"])
    assert.deepEqual(parseServiceConnectivity(text), connectivityDefaults);
});

test("online requires the intended managed HTTPS result", () => {
  for (const change of [{target:"https://example.org/"}, {path:"direct"}, {http_status:302}, {http_status:503},
    {checked_at:null}, {checked_at:0}, {latency_ms:null}, {retry_in_seconds:-1}, {reason:"private error\n"}])
    assert.equal(parseConnectivity({...online, ...change}), null);
});

test("failed and stale observations always warn and retain recovery timing", () => {
  for (const status of ["offline", "degraded", "stale"]) {
    const result = parseConnectivity({...online, status, warning:false, consecutive_failures:4,
      http_status:null, latency_ms:null, last_action:"refresh", action_status:"failed", retry_in_seconds:480});
    assert.equal(result.warning, true);
    assert.equal(result.retryInSeconds, 480);
    assert.equal(result.lastAction, "refresh");
  }
});

test("file export accepts only completed structured results and bounded metadata", () => {
  const good = {path:"/sdcard/Download/MagicNet/MagicNet-diagnostics.txt", bytes:4096};
  assert.deepEqual(parseSupportExport(envelope("support.export", good)), good);
  for (const data of [{...good,bytes:0},{...good,bytes:2**22},{...good,bytes:"4096"},
    {...good,path:"../MagicNet-diagnostics.txt"},{...good,path:"/tmp/secret.txt"},{...good,path:"/bad\n/MagicNet-diagnostics.txt"}])
    assert.equal(parseSupportExport(envelope("support.export", data)), null);
  assert.equal(parseSupportExport(envelope("support.bundle", good)), null);
  assert.equal(parseSupportExport(envelope("support.export", good) + "\n" + envelope("support.export", good)), null);
  assert.equal(parseSupportExport(JSON.stringify({schema:1,ok:false,command:"support.export",error:{code:"support.export_failed"}})), null);
});


test("selected proxy requires independent mixed verification before green status", () => {
  const selected = {...online, path:"selected_proxy", mixed_status:"online"};
  assert.equal(parseConnectivity(selected).status, "online");
  assert.equal(parseConnectivity(selected).path, "selected_proxy");
  for (const mixed_status of [undefined, "failed", "not_run", "unknown"])
    assert.equal(parseConnectivity({...selected, mixed_status}), null);
  const degraded = parseConnectivity({...selected, status:"degraded", reason:"mixed_path_failed",
    mixed_status:"failed", warning:false});
  assert.equal(degraded.warning, true);
  assert.equal(degraded.mixedStatus, "failed");
});

test("unsupported strict core stays unknown and is actionable", () => {
  const result = parseConnectivity({...online, path:"selected_proxy", mixed_status:"not_run",
    status:"unknown", reason:"probe_unsupported", http_status:null, latency_ms:null});
  assert.equal(result.status, "unknown");
  assert.equal(result.warning, true);
});

test("bounded failover status survives the machine boundary", () => {
  const result = parseConnectivity({...online, path:"selected_proxy", mixed_status:"online",
    last_action:"failover", action_status:"ok"});
  assert.equal(result.lastAction, "failover");
  assert.equal(result.actionStatus, "ok");
});
