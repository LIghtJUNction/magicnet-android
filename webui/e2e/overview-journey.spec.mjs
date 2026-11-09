import { test, expect } from "@playwright/test";
import { connectReadOnlyNativeFixture } from "./read-only-native-fixture.mjs";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator(".mn-control")).toBeVisible();
  await connectReadOnlyNativeFixture(page);
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    Object.assign(state, { hasKsu: true, busy: false, phase: "idle", queueDepth: 0, subscriptionReadStatus: "ready" });
    state.backgroundTask.status = "idle";
    Object.assign(state.runtime, { singBoxState: "stopped", serviceReady: false });
    Object.assign(state.subscriptions, { configuredCount: 0, cacheCount: 0, updateRunning: false, updateLockOwner: "none" });
  });
});

test("overview follows confirmed setup progress and opens the built-in node selector", async ({ page }, info) => {
  const next = page.locator(".mn-next-step");
  await expect(next).toHaveAttribute("data-step", "subscriptions");
  await expect(next).toBeInViewport({ ratio: 1 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: info.outputPath("first-use-next-step.png"), fullPage: true, timeout: 20_000 });
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.subscriptions.configuredCount = 2;
  });
  await expect(next).toHaveAttribute("data-step", "update");
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.subscriptions.cacheCount = 24;
  });
  await expect(next).toHaveAttribute("data-step", "start");
  await next.getByRole("button", { name: "启动服务", exact: true }).click();
  await expect(page.getByRole("alertdialog", { name: "确认控制操作" })).toBeVisible();
  await page.getByRole("button", { name: "取消", exact: true }).click();
  await page.locator(".mn-control-destinations").getByRole("button", { name: /切换节点/ }).click();
  await expect(page).toHaveURL(/#\/proxies$/);
  await expect(page.getByRole("heading", { name: "节点与代理组", exact: true })).toBeVisible();
});

test("unknown service status uses a read action and never sends a start or stop", async ({ page }) => {
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.runtime.singBoxState = "unknown";
  });
  await expect(page.locator(".mn-next-step")).toHaveCount(0);
  await expect(page.locator(".mn-control-power")).toHaveText("读取服务状态");
  await page.locator(".mn-control-power").click();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  const requests = await page.evaluate(() => window.__readOnlyNativeFixture.requests);
  expect(requests.some(command => /service (?:start|stop|restart)/.test(command))).toBe(false);
});
