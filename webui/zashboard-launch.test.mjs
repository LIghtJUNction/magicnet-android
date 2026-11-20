import assert from "node:assert/strict";
import test from "node:test";
import { parseZashboardLaunch } from "./src/composables/zashboardLaunch.ts";
import { useExternalLinks } from "./src/composables/useExternalLinks.ts";
import { connectionPresentation } from "./src/lib/servicePresentation.ts";

const url = "http://127.0.0.1:9090";
const webui = url + "/ui/#/setup?hostname=127.0.0.1&port=9090";
const response = (api = {}) => JSON.stringify({ schema: 1, ok: true, command: "service.status",
  data: { api: { ready: true, webui_ready: true, url, webui, ...api },
    readiness: { overall: false }, proxies: ["fail node"] } });
function fixture(payload = response(), verify = "singbox_zashboard=ok", shell = "") {
  const reads = [], intents = [];
  const state = { hasKsu: true, phase: "idle", output: "", notice: "",
    runtime: { singBoxState: "sing-box", api: "http://127.0.0.1:1" } };
  const links = useExternalLinks(state,
    async (...args) => { intents.push(args); return shell; },
    async (...args) => { reads.push(args); return args[0] === "webui verify" ? verify : payload; });
  return { state, links, reads, intents };
}

test("fresh setup URL survives false TUN readiness and failure words in node names", () => {
  assert.deepEqual(parseZashboardLaunch(response()), { ok: true, url: webui, verifyLocalPanel: false });
  const v6 = "http://[::1]:9090";
  assert.equal(parseZashboardLaunch(response({ url: v6,
    webui: v6 + "/ui/#/setup?hostname=::1&port=9090" })).ok, true);
  assert.equal(parseZashboardLaunch(response({ webui_ready: undefined })).verifyLocalPanel, true);
});
test("API, resource and response failures are distinct", () => {
  for (const [input, reason] of [
    [response({ ready: false }), "api_unavailable"],
    [response({ webui_ready: false }), "panel_missing"],
    [response({ ready: null }), "invalid_response"],
    [response({ webui_ready: "yes" }), "invalid_response"],
    ["private malformed secret", "invalid_response"],
    ["[error] errno=1\n" + response(), "invalid_response"],
  ]) assert.deepEqual(parseZashboardLaunch(input), { ok: false, reason });
});
test("addresses reject remote endpoints, credentials, zero ports and conflicting setup", () => {
  for (const api of [
    { url: "", webui }, { webui: "" },
    { url: "javascript:alert(1)", webui: "javascript:alert(1)" },
    { url: "http://example.invalid:9090", webui: "http://example.invalid:9090/ui/" },
    { url: "http://127.0.0.1:0", webui: "http://127.0.0.1:0/ui/" },
    { url: url + "/api" }, { url: "http://user:password@127.0.0.1:9090" },
    { webui: "http://user:password@127.0.0.1:9090/ui/" },
    { webui: "http://127.0.0.1:9091/ui/" }, { webui: url + "/other/" },
    { webui: url + "/ui/?secret=hidden" }, { webui: webui + "&secret=hidden" },
    { webui: webui + "&hostname=elsewhere.invalid" },
    { webui: url + "/ui/#/setup?hostname=elsewhere.invalid&port=9090" },
    { webui: url + "/ui/#/setup?hostname=127.0.0.1&port=80" },
  ]) assert.deepEqual(parseZashboardLaunch(response(api)), { ok: false, reason: "invalid_address" });
});
test("launch uses the machine API and keeps setup out of output, logs and clipboard", async (t) => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const copies = [];
  Object.defineProperty(globalThis, "navigator", { configurable: true,
    value: { clipboard: { writeText: async text => { copies.push(text); } } } });
  t.after(() => descriptor ? Object.defineProperty(globalThis, "navigator", descriptor) : delete globalThis.navigator);
  const f = fixture();
  assert.equal(await f.links.openSingBoxUi("zashboard"), true);
  assert.deepEqual(f.reads.map(args => args[0]), ["--json service status"]);
  assert.equal(f.intents.length, 1);
  assert.ok(f.intents[0][0].includes(webui));
  assert.equal(f.intents[0][2], true);
  assert.doesNotMatch(f.intents[0][3], /hostname|9090/);
  assert.deepEqual(copies, []);
  assert.doesNotMatch(f.state.output + f.state.notice, /hostname|9090|fail node/);
  assert.equal(f.links.openingSingBoxUi.value, false);
});

test("old CLI verifies resources before navigation and rejects missing or contradictory records", async () => {
  const old = response({ webui_ready: undefined });
  const f = fixture(old);
  assert.equal(await f.links.openSingBoxUi("zashboard"), true);
  assert.deepEqual(f.reads.map(args => args[0]), ["--json service status", "webui verify"]);
  assert.equal(f.reads[1][2], true);
  for (const verify of ["", "singbox_zashboard=missing",
    "singbox_zashboard=ok\nsingbox_zashboard=missing", "[error] errno=1\nsingbox_zashboard=ok"]) {
    const failure = fixture(old, verify);
    assert.equal(await failure.links.openSingBoxUi("zashboard"), false);
    assert.equal(failure.intents.length, 0);
    assert.match(failure.links.singBoxUiError.value, /文件缺失/);
  }
});
test("launch failure offers a next step and never reveals raw output", async () => {
  for (const [payload, match] of [
    [response({ ready: false }), /启动服务/],
    [response({ webui_ready: false }), /安装或修复/],
    ["private failure secret=do-not-log", /刷新状态/],
  ]) {
    const f = fixture(payload);
    assert.equal(await f.links.openSingBoxUi("zashboard"), false);
    assert.match(f.links.singBoxUiError.value, match);
    assert.doesNotMatch(f.state.output + f.state.notice, /do-not-log/);
    assert.equal(f.intents.length, 0);
    assert.equal(f.state.phase, "error");
  }
  const failedIntent = fixture(response(), "", "[error] errno=1\nActivity not found");
  assert.equal(await failedIntent.links.openSingBoxUi("zashboard"), false);
  assert.match(failedIntent.links.singBoxUiError.value, /系统浏览器/);
});
test("disconnected and duplicate launches do not enqueue another command", async () => {
  const disconnected = fixture();
  disconnected.state.hasKsu = false;
  assert.equal(await disconnected.links.openSingBoxUi("zashboard"), false);
  assert.equal(disconnected.reads.length, 0);
  let resolve;
  const pending = new Promise(done => { resolve = done; });
  const f = fixture(pending);
  const first = f.links.openSingBoxUi("zashboard");
  assert.equal(f.links.openingSingBoxUi.value, true);
  assert.equal(await f.links.openSingBoxUi("zashboard"), false);
  assert.equal(f.reads.length, 1);
  resolve(response());
  assert.equal(await first, true);
  assert.equal(f.links.openingSingBoxUi.value, false);
});
test("overview and shell distinguish network failure from service readiness", () => {
  const running = { singBoxState: "sing-box", serviceReady: true };
  assert.equal(connectionPresentation(running, true, { status: "offline", warning: true }).label, "连接需要处理");
  assert.equal(connectionPresentation(running, true, { status: "online", warning: false }).label, "网络已连接");
  assert.equal(connectionPresentation({ ...running, singBoxState: "stopped" }, true,
    { status: "online", warning: false }).label, "已停止");
  assert.equal(connectionPresentation({ ...running, serviceReady: false }, true,
    { status: "online", warning: false }).label, "服务未就绪");
  assert.equal(connectionPresentation(running, false, { status: "online", warning: false }).label, "未连接设备");
});
