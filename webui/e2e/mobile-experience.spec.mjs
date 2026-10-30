import { expect, test } from "@playwright/test";
import { connectReadOnlyNativeFixture } from "./read-only-native-fixture.mjs";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
    localStorage.setItem("magicnet.webui.theme", "light");
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator(".mn-control")).toBeVisible();
});

test("the current phone workspace exposes subpages without losing drafts or history", async ({ page }) => {
  test.skip(page.viewportSize().width >= 900, "The desktop rail already exposes every page.");
  const configure = page.locator('.mobile-nav [data-workspace="configure"]');
  const routing = page.locator('.mobile-nav [data-workspace="route"]');
  const sheet = page.getByRole("dialog", { name: "配置分区", exact: true });

  // The first tap still opens subscriptions directly.
  await configure.click();
  await expect(page).toHaveURL(/#\/subs$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const subscription = page.getByRole("textbox", { name: "订阅链接，每行一个", exact: true });
  const subscriptionDraft = "https://example.invalid/mobile-a\nhttps://example.invalid/mobile-b";
  await subscription.fill(subscriptionDraft);

  await configure.click();
  await expect(sheet).toBeVisible();
  await expect(configure).toHaveAttribute("aria-expanded", "true");
  await expect(sheet.locator('[data-page="subs"]')).toHaveAttribute("aria-current", "page");
  const close = sheet.getByRole("button", { name: "关闭页面导航", exact: true });
  await expect(close).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(sheet.locator('[data-page="webui"]')).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(close).toBeFocused();
  await close.click();
  await expect(sheet).toBeHidden();
  await expect(configure).toBeFocused();
  await expect(page.locator("body")).not.toHaveCSS("overflow", "hidden");

  await configure.click();
  await sheet.locator('[data-page="config"]').click();
  await expect(page).toHaveURL(/#\/config$/);
  await expect(sheet).toBeHidden();
  await expect(page.getByRole("heading", { name: "配置文件", exact: true })).toBeInViewport();
  const editor = page.locator(".json-editor__textarea");
  const configDraft = '{\n  "log": { "level": "info" }\n}';
  await editor.fill(configDraft);
  if (page.viewportSize().width < 640) {
    await expect(editor).toHaveCSS("font-size", "16px");
    await expect(editor).toHaveCSS("line-height", "24px");
    const editorBounds = await editor.boundingBox();
    expect(editorBounds.height).toBeGreaterThanOrEqual(192);
    expect(editorBounds.height).toBeLessThanOrEqual(page.viewportSize().height * 0.52 + 1);
  }

  await routing.click();
  await expect(page).toHaveURL(/#\/apps$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await configure.click();
  await expect(page).toHaveURL(/#\/subs$/);
  await expect(subscription).toHaveValue(subscriptionDraft);
  await configure.click();
  await sheet.locator('[data-page="config"]').click();
  await expect(editor).toHaveValue(configDraft);

  await page.goBack();
  await expect(page).toHaveURL(/#\/subs$/);
  await expect(subscription).toHaveValue(subscriptionDraft);
  await configure.click();
  await expect(sheet).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(sheet).toBeHidden();
  await expect(configure).toBeFocused();
  await expect(configure).toHaveAttribute("aria-expanded", "false");

  // Rotation can remove the original bottom-bar focus target while the sheet is open.
  await configure.click();
  await expect(sheet).toBeVisible();
  await page.setViewportSize({ width: 900, height: 390 });
  await expect(configure).toBeHidden();
  const desktopCurrentPage = page.locator('.desktop-rail [data-tab="subs"]');
  await expect(desktopCurrentPage).toBeVisible();
  await close.click();
  await expect(sheet).toBeHidden();
  await expect(desktopCurrentPage).toBeFocused();
  await expect(page).toHaveURL(/#\/subs$/);
});

test("quick jump stays dismissible by touch in a shortened visible viewport", async ({ page }) => {
  test.skip(page.viewportSize().width >= 900, "Phone keyboard layout.");
  const trigger = page.getByRole("button", { name: "快速跳转", exact: true });
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "快速跳转", exact: true });
  const search = dialog.getByRole("combobox", { name: "搜索页面和操作", exact: true });
  await search.fill("配置");
  const original = page.viewportSize();
  // This verifies a resized viewport, not a physical Android keyboard.
  await page.setViewportSize({ width: original.width, height: Math.max(240, original.height - 280) });
  await expect(page.locator(".mobile-nav")).toBeHidden();
  await expect(search).toBeInViewport({ ratio: 1 });
  const close = dialog.getByRole("button", { name: "关闭快速跳转", exact: true });
  await expect(close).toBeInViewport({ ratio: 1 });
  const closeBounds = await close.boundingBox();
  expect(closeBounds.width).toBeGreaterThanOrEqual(48);
  expect(closeBounds.height).toBeGreaterThanOrEqual(48);
  await expect(dialog).toBeInViewport({ ratio: 1 });

  await close.click();
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
  await expect(page.locator("body")).not.toHaveCSS("overflow", "hidden");
  await page.setViewportSize(original);
  await expect(page.locator(".mobile-nav")).toBeVisible();

  const currentUrl = page.url();
  await trigger.click();
  await search.fill("配置文件");
  await expect(dialog.getByRole("option", { name: /配置文件/ })).toBeVisible();
  await search.press("Tab");
  await expect(close).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
  await expect(page).toHaveURL(currentUrl);
  await expect(page.locator(".mn-control")).toBeVisible();
});

test("application batches expose every result while selection remains limited to visible rows", async ({ page }) => {
  await page.goto("/#/apps", { waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "应用名单", exact: true })).toBeVisible();
  await connectReadOnlyNativeFixture(page);
  await page.evaluate(async () => {
    const { state } = (await import("/src/composables/useMagicNet.ts")).useMagicNet();
    state.hasKsu = true;
    state.packageQuery = "";
    state.packages = Array.from({ length: 135 }, (_, index) => {
      const number = String(index + 1).padStart(3, "0");
      return { packageName: `com.example.mobile${number}`, appLabel: `Example app ${number}` };
    });
  });
  const rows = page.getByRole("checkbox", { name: /^选择 com\.example\.mobile\d{3}$/ });
  const more = page.getByRole("button", { name: /^显示更多应用/ });
  await expect(rows).toHaveCount(40);
  await expect(page.getByText("已显示 40 / 135 个应用", { exact: true })).toBeVisible();
  await rows.first().check();
  await page.getByRole("button", { name: "选择可见项", exact: true }).click();
  await expect(page.getByText("已选 40 个", { exact: true })).toBeVisible();

  await more.click();
  await expect(rows).toHaveCount(80);
  await expect(rows.nth(39)).toBeChecked();
  await expect(rows.nth(40)).not.toBeChecked();
  await expect(page.getByText("已选 40 个", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除已选应用", exact: true }).click();
  await more.click();
  await expect(rows).toHaveCount(120);
  await more.click();
  await expect(rows).toHaveCount(135);
  await expect(page.getByRole("checkbox", { name: "选择 com.example.mobile135", exact: true })).toBeVisible();
  await expect(more).toHaveCount(0);

  const search = page.getByRole("searchbox", { name: "搜索已安装应用包名", exact: true });
  await search.fill("mobile135");
  await expect(rows).toHaveCount(1);
  await expect(page.getByText("已显示 1 / 1 个应用", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除搜索", exact: true }).click();
  await expect(rows).toHaveCount(40);
  await expect(search).toBeFocused();
  await expect(page.getByText("已显示 40 / 135 个应用", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.__readOnlyNativeFixture.requests.filter(
    command => /\bapp (?:add(?:-many)?|remove|reapply)\b/.test(command),
  ))).toEqual([]);
});
