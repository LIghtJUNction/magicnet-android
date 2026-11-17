import { expect, test } from "@playwright/test";
import { navigateToPage } from "./navigation.mjs";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator(".mn-control")).toBeVisible();
});

test("four everyday pages are direct links and More keeps all remaining pages reachable", async ({ page }) => {
  const desktop = await page.locator(".desktop-rail").isVisible();
  const nav = page.locator(desktop ? ".desktop-rail" : ".mobile-nav");
  await expect(nav.locator("[data-tab]:visible")).toHaveCount(4);
  for (const tab of ["proxies", "subs", "apps", "control"]) {
    await nav.locator(`[data-tab="${tab}"]`).click();
    await expect(page.locator(".page-surface")).toHaveAttribute("data-page", tab);
    await nav.locator(`[data-tab="${tab}"]`).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
  }
  for (const tab of ["about", "block", "chain", "tailscale", "config", "webui", "health", "terminal", "tools", "output"]) {
    await navigateToPage(page, tab);
    await expect(page.locator(".page-surface")).toHaveAttribute("data-page", tab);
    await expect(page.locator(".page-surface h2").first()).toBeVisible();
  }
});

test("overview puts connection controls first and reveals network settings on request", async ({ page }, info) => {
  await expect(page.locator(".mn-control-power")).toBeVisible();
  await expect(page.locator(".mn-control-power")).toBeDisabled();
  await expect(page.locator(".mn-control-status h2")).toHaveText("未连接设备");
  await expect(page.locator(".mn-service-facts")).toBeHidden();
  const mode = page.getByRole("button", { name: "eBPF", exact: true });
  await expect(mode).toBeHidden();
  await expect(page.getByRole("switch", { name: "允许热点使用代理" })).toBeHidden();
  await expect(page.getByRole("button", { name: "重启服务", exact: true })).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: info.outputPath("daily-overview.png"), fullPage: true });
  await page.locator(".mn-section-disclosure > summary").filter({ hasText: "网络设置" }).click();
  await expect(mode).toBeVisible();
  await expect(mode).toBeDisabled();
  await expect(page.getByRole("switch", { name: "允许热点使用代理" })).toBeVisible();
  await page.getByRole("button", { name: "检查网络", exact: true }).click();
  await expect(page).toHaveURL(/#\/health$/);
  await expect(page.getByRole("heading", { name: "诊断", exact: true })).toBeVisible();
});
