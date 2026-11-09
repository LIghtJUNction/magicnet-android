import assert from "node:assert/strict";
import test from "node:test";
import { controlNextStep } from "./src/components/pages/controlNextStep.ts";

const stopped = {
  connected: true, busy: false, runtime: { singBoxState: "stopped" },
  subscriptionReadStatus: "ready",
  subscriptions: { configuredCount: 0, cacheCount: 0, sourceMode: "url", lastResult: "never", updateRunning: false, updateLockOwner: "none" },
};

test("unread or failed subscriptions offer a read, never assume an empty device", () => {
  for (const subscriptionReadStatus of ["idle", "loading", "error"]) {
    assert.equal(controlNextStep({ ...stopped, subscriptionReadStatus }).action, "refresh");
  }
});

test("confirmed empty, configured and cached states have distinct next actions", () => {
  assert.equal(controlNextStep(stopped).action, "subscriptions");
  const configured = { ...stopped, subscriptions: { ...stopped.subscriptions, configuredCount: 2 } };
  assert.equal(controlNextStep(configured).action, "update");
  assert.equal(controlNextStep({ ...configured, subscriptions: { ...configured.subscriptions, cacheCount: 24 } }).action, "start");
});

test("a retained cache can start even when its subscription source was removed", () => {
  assert.equal(controlNextStep({ ...stopped, subscriptions: { ...stopped.subscriptions, cacheCount: 12 } }).action, "start");
});

test("a successful local file import can start without a remote download cache", () => {
  const subscriptions = { ...stopped.subscriptions, sourceMode: "local", configuredCount: 1, lastResult: "success" };
  assert.equal(controlNextStep({ ...stopped, subscriptions }).action, "start");
  const failed = controlNextStep({ ...stopped, subscriptions: { ...subscriptions, lastResult: "failed" } });
  assert.equal(failed.action, "update");
  assert.match(failed.detail, /本地订阅文件/);
});

test("a working custom configuration is not described as missing subscriptions", () => {
  assert.equal(controlNextStep({ ...stopped, runtime: { singBoxState: "sing-box" } }), null);
});

test("unknown process state, disconnected previews and current work do not suggest mutations", () => {
  assert.equal(controlNextStep({ ...stopped, runtime: { singBoxState: "unknown" } }), null);
  assert.equal(controlNextStep({ ...stopped, connected: false }), null);
  assert.equal(controlNextStep({ ...stopped, busy: true }), null);
  assert.equal(controlNextStep({ ...stopped, subscriptions: { ...stopped.subscriptions, updateRunning: true } }), null);
  for (const updateLockOwner of ["active", "pending", "unknown"]) {
    assert.equal(controlNextStep({ ...stopped, subscriptions: { ...stopped.subscriptions, updateLockOwner } }), null);
  }
});
