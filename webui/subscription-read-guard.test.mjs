import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";
import { computed, nextTick, reactive, ref, shallowRef, watch } from "vue";
import { useActionLock } from "./src/composables/useActionLock.ts";
import { subscriptionDefaults } from "./src/composables/parsers.ts";
import * as plans from "./src/components/pages/subscriptionPreview.ts";
import * as localFiles from "./src/components/pages/localSubscriptionFile.ts";
import { execFailed } from "./src/utils.ts";
import { backgroundTaskBlocksLaunch, subscriptionLifecycleRunning, isSubscriptionBackgroundArgs } from "./src/composables/backgroundTasks.ts";

function fixture(readStatus = "error") {
  const source = readFileSync(new URL("./src/components/pages/SubscriptionsPage.vue", import.meta.url), "utf8");
  const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1]
    .replace(/^import[\s\S]*?;\s*$/gm, "");
  const code = ts.transpileModule(script, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
  }).outputText;
  const state = reactive({ hasKsu: true, busy: false, queueDepth: 0, subscriptionReadStatus: readStatus,
    subscriptions: { ...subscriptionDefaults, singBoxUrls: [], filters: [] },
    backgroundTask: { status: "idle", args: "" } });
  const calls = [];
  const stops = [];
  const dependencies = {
    ...plans, ...localFiles, computed, nextTick, ref, shallowRef,
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop; },
    t: (value) => value, useActionLock, execFailed, backgroundTaskBlocksLaunch, subscriptionLifecycleRunning, isSubscriptionBackgroundArgs,
    pendingSubscriptionDraft: ref(null), takePendingSubscriptionDraft: () => null,
    buildSubscriptionUsageOverview: () => [],
    useMagicNet: () => ({
      state,
      startPrivateBackgroundCli: async (args) => { calls.push(args); return "[accepted] id=fixture"; },
      startBackgroundCli: async (args) => { calls.push(args); return "[accepted] id=fixture"; },
      stagePrivatePayload: async () => { calls.push("stage"); return { basename: "fixture.b64" }; },
      removePrivatePayload: async () => { calls.push("remove"); return true; },
      runPrivateCli: async (args) => { calls.push(args); return { ok: true }; },
      refreshSubs: async () => true,
    }),
  };
  const controller = new Function(...Object.keys(dependencies), code + `
    return { draft: singBoxText, dirty, confirmClear, canWrite, editorOpen, userAgentCardRef,
      apply: applySubscriptions, clear: clearSubscriptions,
      importFile: importLocalSubscriptions, update: updateSubscriptions };`
  )(...Object.values(dependencies));
  return { ...controller, state, calls, stop: () => stops.forEach((stop) => stop()) };
}

test("source writes cannot supersede a foreground, queued or unresolved background operation", async () => {
  for (const blocker of [
    { busy: true }, { queueDepth: 1 },
    { backgroundTask: { status: "running", args: "service start" } },
    { backgroundTask: { status: "timeout", args: "service start" } },
  ]) {
    const f = fixture("ready");
    try {
      Object.assign(f.state, blocker);
      f.draft.value = "https://draft.example/sub";
      await f.apply();
      await f.importFile({ target: { files: [{ name: "source.txt", size: 1 }], value: "source.txt" } });
      f.state.subscriptions.configuredCount = 1;
      await f.update();
      f.draft.value = "";
      f.confirmClear.value = true;
      await f.clear();
      assert.deepEqual(f.calls, []);
    } finally { f.stop(); }
  }
});

test("source apply can save User-Agent and then stage without blocking its own action", async () => {
  const f = fixture("ready");
  try {
    f.draft.value = "https://draft.example/sub";
    f.userAgentCardRef.value = { userAgentChanged: true, persistUserAgent: async () => {
      f.state.busy = true;
      f.state.queueDepth = 1;
      await nextTick();
      f.state.busy = false;
      f.state.queueDepth = 0;
      f.calls.push("persist-user-agent");
      return true;
    } };
    await f.apply();
    assert.deepEqual(f.calls.slice(0, 2), ["persist-user-agent", "stage"]);
    assert.match(f.calls[2], /^webui payload apply-subscription /);
  } finally { f.stop(); }
});

for (const status of ["idle", "loading", "error"]) {
  test(`${status} subscription observations block every source write but keep the draft`, async () => {
    const f = fixture(status);
    try {
      f.draft.value = "https://draft.example/sub";
      await f.apply();
      const file = { target: { files: [{ name: "source.txt", size: 1, arrayBuffer: () => { throw Error("must not read an unapproved import"); } }], value: "source.txt" } };
      await f.importFile(file);
      f.state.subscriptions.configuredCount = 1;
      await f.update();
      assert.deepEqual(f.calls, []);
      f.draft.value = "";
      f.confirmClear.value = true;
      await f.clear();
      assert.deepEqual(f.calls, [], "clear must also fail closed when called directly");
    } finally { f.stop(); }
  });

  test(`${status} recovery reads existing sources without discarding an early draft`, async () => {
    const f = fixture(status);
    try {
      f.draft.value = "https://draft.example/sub";
      f.state.subscriptions.singBoxUrls = ["https://existing.example/sub"];
      f.state.subscriptions.configuredCount = 1;
      f.state.subscriptionReadStatus = "ready";
      await nextTick();
      assert.equal(f.draft.value, "https://draft.example/sub");
      assert.equal(f.dirty.value, true);
      assert.equal(f.editorOpen.value, true, "the draft stays visible when existing sources are discovered");
      assert.equal(f.canWrite.value, true);
      await f.apply();
      assert.equal(f.calls[0], "stage");
      assert.match(f.calls[1], /^webui payload apply-subscription /);
    } finally { f.stop(); }
  });
}

test("a failed read invalidates an open clear confirmation and preserves an existing draft", async () => {
  const f = fixture("ready");
  try {
    f.state.subscriptions.singBoxUrls = ["https://existing.example/sub"];
    f.state.subscriptions.configuredCount = 1;
    await nextTick();
    f.draft.value = "";
    await f.apply();
    assert.equal(f.confirmClear.value, true);
    f.state.subscriptionReadStatus = "error";
    await nextTick();
    assert.equal(f.confirmClear.value, false);
    await f.clear();
    assert.deepEqual(f.calls, []);
    f.state.subscriptionReadStatus = "ready";
    await nextTick();
    assert.equal(f.draft.value, "");
    assert.equal(f.dirty.value, true);
  } finally { f.stop(); }
});
