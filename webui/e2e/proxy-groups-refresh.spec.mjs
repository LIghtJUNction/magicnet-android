import { expect, test } from "@playwright/test";

async function mountCachedPanel(page, holdReads = false) {
  await page.route("**/e2e/proxy-refresh-fixture.html", (route) => route.fulfill({
    contentType: "text/html",
    body: '<!doctype html><html lang="zh-CN"><meta name="viewport" content="width=device-width, initial-scale=1"><body><main id="proxy-fixture" style="padding:16px"></main></body></html>',
  }));
  await page.goto("/e2e/proxy-refresh-fixture.html");
  await page.evaluate(async (hold) => {
    const fixture = window.__proxyRefresh = {
      nodes: ["HK-excluded", "JP-kept"], calls: 0, hold, pending: [], show: null,
    };
    window.ksu = {
      spawn(command, _args, _options, callbackName) {
        const callback = window[callbackName];
        if (!command.includes("api proxies")) {
          callback.emit("exit", 1);
          return;
        }
        fixture.calls += 1;
        // Capture the response when the request starts, not when a held read ends.
        const output = JSON.stringify({ proxies: {
          proxy: { type: "Selector", now: "JP-kept", all: [...fixture.nodes] },
        } });
        const respond = () => {
          callback.stdout.emit("data", output);
          callback.emit("exit", 0);
        };
        if (fixture.hold) fixture.pending.push(respond);
        else setTimeout(respond, 0);
      },
    };
    const { createApp, h, ref, KeepAlive } = await import("/e2e/vue-fixture.mjs");
    await import("/src/styles.css");
    const { setLocale } = await import("/src/i18n/index.ts");
    setLocale("zh-CN");
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.hasKsu = true;
    const { default: Panel } = await import("/src/components/pages/ProxyGroupsPanel.vue");
    const visible = ref(true);
    fixture.show = (value) => { visible.value = value; };
    const SubscriptionPage = { render: () => h("p", "subscription settings fixture") };
    createApp({
      render: () => h(KeepAlive, null, {
        default: () => visible.value
          ? h(Panel, { key: "proxies" })
          : h(SubscriptionPage, { key: "subscriptions" }),
      }),
    }).mount("#proxy-fixture");
  }, holdReads);
}

async function leaveAndApplyExclusions(page) {
  await page.evaluate(() => window.__proxyRefresh.show(false));
  await expect(page.getByText("subscription settings fixture", { exact: true })).toBeVisible();
  await page.evaluate(async () => {
    window.__proxyRefresh.nodes = ["JP-kept", "US-kept"];
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.subscriptions.filters = ["HK"];
    state.subscriptions.lastGenerationId = "new-generation";
    state.subscriptions.lastResult = "success";
    window.__proxyRefresh.show(true);
  });
}

test("returning to a cached proxy panel refreshes excluded nodes and preserves its search", async ({ page }) => {
  await mountCachedPanel(page);
  await expect(page.getByRole("button", { name: "HK-excluded", exact: true })).toBeVisible();
  await page.getByPlaceholder("搜索代理组或节点").fill("proxy");
  expect(await page.evaluate(() => window.__proxyRefresh.calls)).toBe(1);

  await leaveAndApplyExclusions(page);

  await expect(page.getByRole("button", { name: "US-kept", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "HK-excluded", exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder("搜索代理组或节点")).toHaveValue("proxy");
  expect(await page.evaluate(() => window.__proxyRefresh.calls)).toBe(2);
});

test("returning during an old read ignores its response and requests the new snapshot", async ({ page }) => {
  await mountCachedPanel(page, true);
  await expect.poll(() => page.evaluate(() => window.__proxyRefresh.pending.length)).toBe(1);
  expect(await page.evaluate(() => window.__proxyRefresh.calls)).toBe(1);

  await leaveAndApplyExclusions(page);
  await page.evaluate(() => window.__proxyRefresh.pending.shift()());

  await expect.poll(() => page.evaluate(() => window.__proxyRefresh.calls)).toBe(2);
  await expect.poll(() => page.evaluate(() => window.__proxyRefresh.pending.length)).toBe(1);
  await expect(page.getByRole("button", { name: "HK-excluded", exact: true })).toHaveCount(0);
  await page.evaluate(() => window.__proxyRefresh.pending.shift()());
  await expect(page.getByRole("button", { name: "US-kept", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "HK-excluded", exact: true })).toHaveCount(0);
});
