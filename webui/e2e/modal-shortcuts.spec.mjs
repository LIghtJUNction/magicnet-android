import { expect, test } from "@playwright/test";
import { connectReadOnlyNativeFixture } from "./read-only-native-fixture.mjs";

test("control confirmation owns shortcuts until it closes", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator(".mn-control")).toBeVisible();

  // Load the lazy palette first so a forbidden second modal cannot hide behind
  // an unresolved import. The ordinary shortcut must still work outside dialogs.
  const palette = page.getByRole("dialog", { name: "快速跳转", exact: true });
  await page.keyboard.press("Control+k");
  await expect(palette).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(palette).toHaveCount(0);

  await connectReadOnlyNativeFixture(page);
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    Object.assign(state, { hasKsu: true, busy: false, phase: "idle", queueDepth: 0 });
    Object.assign(state.runtime, { singBoxState: "sing-box", singBox: "123", serviceReady: true });
  });
  const stop = page.getByRole("button", { name: "停止服务", exact: true });
  await expect(stop).toBeEnabled();
  await stop.click();

  const confirmation = page.getByRole("alertdialog", { name: "确认控制操作", exact: true });
  const cancel = confirmation.getByRole("button", { name: "取消", exact: true });
  const confirm = confirmation.getByRole("button", { name: "继续执行", exact: true });
  await expect(confirmation).toBeVisible();
  await expect(cancel).toBeFocused();
  await expect(page.locator("body")).toHaveCSS("overflow", "hidden");

  for (const shortcut of ["Control+k", "Meta+k", "/"]) {
    await page.keyboard.press(shortcut);
    await expect(palette).toHaveCount(0);
    await expect(confirmation).toBeVisible();
    await expect(cancel).toBeFocused();
  }
  await page.keyboard.press("Shift+Tab");
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(confirmation).toHaveCount(0);
  await expect(stop).toBeFocused();
  await expect(page.locator("body")).not.toHaveCSS("overflow", "hidden");

  await page.keyboard.press("Control+k");
  await expect(palette).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(palette).toHaveCount(0);
  await expect(stop).toBeFocused();
  expect(await page.evaluate(() => window.__readOnlyNativeFixture.requests.filter(
    (command) => /\bservice (?:start|stop|restart)\b/.test(command),
  ))).toEqual([]);
});
