import { test, expect } from "@playwright/test";
import { navigateToPage } from "./navigation.mjs";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator(".mn-control")).toBeVisible();
  await page.evaluate(async () => {
    window.__dashboardFixture = { apiReady: true, panelReady: true, commands: [] };
    window.ksu = {
      spawn(command, _args, _options, callbackName) {
        const fixture = window.__dashboardFixture;
        fixture.commands.push(command);
        setTimeout(() => {
          const callback = window[callbackName];
          if (!callback) return;
          const service = command.includes("--json service status");
          const intent = command.includes("am start");
          const payload = service
            ? { schema: 1, ok: true, command: "service.status", data: {
              api: { ready: fixture.apiReady, webui_ready: fixture.panelReady,
                url: "http://127.0.0.1:9090", webui: "http://127.0.0.1:9090/ui/#/setup?hostname=127.0.0.1&port=9090" },
              readiness: { overall: false },
            } }
            : { schema: 1, ok: false, command: "machine.error",
              error: { code: "machine.unsupported_command", message: "Browser fixture." } };
          callback.stdout.emit("data", intent ? "" : JSON.stringify(payload));
          callback.emit("exit", service || intent ? 0 : 1);
        }, 0);
      },
    };
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    Object.assign(state, { hasKsu: true, busy: false, phase: "idle", queueDepth: 0, subscriptionReadStatus: "ready" });
    state.backgroundTask.status = "idle";
    Object.assign(state.runtime, { singBoxState: "sing-box", serviceReady: true,
      singBoxRssKib: 15600, transparentMode: "tun", transparentEffectiveMode: "tun",
      transparentDataplaneReady: true, transparentRecentError: "" });
    Object.assign(state.subscriptions, { configuredCount: 1, cacheCount: 48, updateRunning: false, updateLockOwner: "none" });
    Object.assign(state.connectivity, { status: "online", warning: false, path: "selected_proxy",
      reason: "ok", latencyMs: 58, checkedAt: null, mixedStatus: "online" });
  });
});

test("overview opens a configured local Zashboard and keeps common destinations reachable", async ({ page }, info) => {
  await expect(page.getByRole("heading", { name: "网络已连接", exact: true })).toBeVisible();
  const open = page.locator(".mn-dashboard-open");
  await expect(open).toBeInViewport({ ratio: 1 });
  const globalOpen = page.locator(".mn-dashboard-global");
  const compactToolbar = page.viewportSize().width <= 639;
  await expect(page.getByRole("button", { name: "快速跳转", exact: true })).toBeInViewport();
  if (compactToolbar) await expect(globalOpen).toBeHidden();
  else await expect(globalOpen).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: info.outputPath("overview-online.png"), fullPage: true });
  await open.click();
  await expect.poll(() => page.evaluate(() => window.__dashboardFixture.commands.filter(value => value.includes("am start")).length)).toBe(1);
  const commands = await page.evaluate(() => window.__dashboardFixture.commands);
  expect(commands.some(value => value.includes("api groups"))).toBe(false);
  expect(commands.find(value => value.includes("am start"))).toContain("#/setup?hostname=127.0.0.1&port=9090");
  if (!compactToolbar) {
    await globalOpen.click();
    await expect.poll(() => page.evaluate(() => window.__dashboardFixture.commands.filter(value => value.includes("am start")).length)).toBe(2);
  }
  for (const [tab, selector] of [["subs", ".page-surface[data-page='subs']"],
    ["proxies", ".page-surface[data-page='proxies']"],
    ["health", ".page-surface[data-page='health']"], ["webui", ".page-surface[data-page='webui']"]]) {
    await navigateToPage(page, tab);
    await expect(page.locator(selector)).toBeVisible();
  }
  await expect(page.locator(".mn-panel-maintenance")).not.toHaveAttribute("open", "");
  await page.screenshot({ path: info.outputPath("dashboard-manager.png"), fullPage: true });
});

test("missing panel gives a repair path and network failure is prominent", async ({ page }, info) => {
  await page.evaluate(async () => {
    window.__dashboardFixture.panelReady = false;
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    Object.assign(state.connectivity, { status: "offline", warning: true, reason: "upstream_unavailable" });
  });
  await expect(page.getByRole("heading", { name: "连接需要处理", exact: true })).toBeVisible();
  await page.locator(".mn-dashboard-open").click();
  await expect(page.locator(".mn-dashboard-error")).toContainText("Zashboard 文件缺失");
  expect(await page.evaluate(() => window.__dashboardFixture.commands.some(value => value.includes("am start")))).toBe(false);
  await page.screenshot({ path: info.outputPath("overview-recovery.png"), fullPage: true });
  await page.getByRole("button", { name: "面板设置与修复", exact: true }).click();
  await expect(page.locator(".mn-panel-launch-error")).toContainText("Zashboard 文件缺失");
  await page.locator(".mn-panel-launch-error").getByRole("button", { name: "安装与修复", exact: true }).click();
  await expect(page.locator(".mn-panel-maintenance")).toHaveAttribute("open", "");
  await expect(page.getByRole("button", { name: "后台下载并安装", exact: true })).toBeVisible();
});

test("English dark overview keeps the dashboard action readable", async ({ page }, info) => {
  await page.evaluate(async () => {
    (await import("/src/i18n/index.ts")).setLocale("en");
    document.documentElement.dataset.theme = "dark";
  });
  await expect(page.locator(".mn-dashboard-open")).toHaveText(/Open Zashboard/);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: info.outputPath("overview-dark-en.png"), fullPage: true });
});

test("exclusion keywords display import counts and clearing is a draft", async ({ page }, info) => {
  await navigateToPage(page, "subs");
  await expect(page.locator(".page-surface[data-page='subs']")).toBeVisible();
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.subscriptionReadStatus = "ready";
    state.busy = false;
    Object.assign(state.subscriptions, { configuredCount: 1, cacheCount: 2, filters: ["HK", "TW"],
      lastAttemptEpoch: 1795000000, lastImportedCount: 2, lastSkippedCount: 46 });
  });
  await page.locator(".settings-section > summary").filter({ hasText: "订阅设置" }).click();
  await expect(page.getByRole("heading", { name: "排除节点", exact: true })).toBeVisible();
  await expect(page.getByTestId("subscription-filter-counts")).toContainText("最近一次导入 2 个，跳过 46 个");
  const exclude = page.locator('button[data-filter-value="HK"][aria-pressed]');
  await expect(exclude).toHaveText("排除 HK");
  await expect(exclude).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "清空排除词", exact: true }).click();
  await expect(exclude).toHaveAttribute("aria-pressed", "false");
  expect(await page.evaluate(async () => (await import("/src/composables/useMagicNet.ts")).useMagicNet().state.subscriptions.filters)).toEqual(["HK", "TW"]);
  expect(await page.evaluate(() => window.__dashboardFixture.commands.some(value => /sub filter (?:set|clear)/.test(value)))).toBe(false);
  await expect(page.getByTestId("subscription-filter").getByRole("button", { name: "保存并应用排除词", exact: true })).toBeEnabled();
  await page.screenshot({ path: info.outputPath("subscription-exclusions.png"), fullPage: true });
});
