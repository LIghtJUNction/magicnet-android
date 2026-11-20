import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import { computed, reactive, ref, watch } from "vue";
import { decodeMachineData, machineErrorCode } from "./src/composables/machineStatus.ts";
import { object, parseOverlay, parseTargets, ROUTING_KEY, validRoutingValue } from "./src/components/pages/routingEditor.ts";

const source = readFileSync(new URL("./src/components/pages/RoutingEditor.vue", import.meta.url), "utf8");
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*;\n/gm, "");
const code = ts.transpileModule(script + "\nglobalThis.fixture = { load, endpoint, overlay, editOutbound, addOutbound, preview, failed };", {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function setup(outbounds = []) {
  const payloads = [];
  const response = (command, data) => ({ ok: true, stdout: JSON.stringify({ schema: 1, ok: true, command, data }) });
  const context = vm.createContext({
    computed, reactive, ref, watch, onMounted() {},
    object, parseOverlay, parseTargets, ROUTING_KEY, validRoutingValue, decodeMachineData, machineErrorCode,
    t: (text) => text, shellQuote: JSON.stringify, Error,
    useMagicNet: () => ({
      state: { packages: [] }, refreshStatus: async () => true, refreshPackages: async () => true,
      async runPrivateCli(command) {
        if (command === "--json capabilities") return response("machine.capabilities", { features: ["additive_routing_overlay"] });
        if (command === "--json override inspect") return response("override.inspect", {
          configured_revision: 1, pending: false,
          patch: { [ROUTING_KEY]: { schema: 1, rules: [], outbounds } },
          routing_targets: [{ tag: "proxy", type: "selector" }, { tag: "direct", type: "direct" }],
        });
        assert.match(command, /^--json override preview-file /);
        return response("override.preview", { valid: true });
      },
      async stagePrivatePayload(_namespace, basename, content) {
        payloads.push(JSON.parse(content));
        return { basename, path: "/private/routing.json" };
      },
      async removePrivatePayload() { return true; },
    }),
  });
  vm.runInContext(code, context);
  return { f: context.fixture, payloads };
}

test("changing protocol omits credential inputs hidden by the selected outbound form", async () => {
  for (const type of ["vless", "trojan", "shadowsocks"]) {
    const { f, payloads } = setup();
    await f.load();
    Object.assign(f.endpoint, {
      type: "http", tag: `outbound-${type}`, server: "proxy.example.invalid", port: "443",
      username: "http-only-user", password: "sample-password",
    });
    f.endpoint.type = type;
    f.endpoint.uuid = "5c8e8752-e1d2-45b6-b028-35b002a8c4ef";
    f.addOutbound();
    await f.preview();
    assert.equal(f.failed.value, false);
    const outbound = payloads[0].patch[ROUTING_KEY].outbounds[0];
    assert.equal(Object.hasOwn(outbound, "username"), false, `${type} has no username input`);
    if (type === "vless") {
      assert.equal(Object.hasOwn(outbound, "password"), false);
      assert.equal(outbound.uuid, "5c8e8752-e1d2-45b6-b028-35b002a8c4ef");
    } else assert.equal(outbound.password, "sample-password");
  }
});

test("editing URL-test group members retains the configured URL and interval", async () => {
  const original = {
    tag: "custom-urltest", type: "urltest", outbounds: ["proxy"],
    url: "https://probe.example.invalid/check", interval: "10m",
  };
  const { f, payloads } = setup([original]);
  await f.load();
  f.editOutbound(f.overlay.value.outbounds[0]);
  f.endpoint.members = "proxy, direct";
  f.addOutbound();
  await f.preview();
  assert.deepEqual(payloads[0].patch[ROUTING_KEY].outbounds[0], { ...original, outbounds: ["proxy", "direct"] });
});

test("new URL-test groups receive probe defaults", async () => {
  const { f, payloads } = setup();
  await f.load();
  Object.assign(f.endpoint, { type: "urltest", tag: "new-urltest", members: "proxy, direct" });
  f.addOutbound();
  await f.preview();
  const outbound = payloads[0].patch[ROUTING_KEY].outbounds[0];
  assert.equal(outbound.url, "https://www.gstatic.com/generate_204");
  assert.equal(outbound.interval, "3m");
});

test("editing an HTTP endpoint retains its visible credentials and TLS settings", async () => {
  const original = {
    tag: "http-proxy", type: "http", server: "proxy.example.invalid", server_port: 443,
    username: "sample-user", password: "sample-password",
    tls: { enabled: true, server_name: "proxy.example.invalid", alpn: ["h2"] },
  };
  const { f, payloads } = setup([original]);
  await f.load();
  f.editOutbound(f.overlay.value.outbounds[0]);
  f.endpoint.port = "8443";
  f.addOutbound();
  await f.preview();
  assert.deepEqual(payloads[0].patch[ROUTING_KEY].outbounds[0], { ...original, server_port: 8443 });
});
