import { navigateToPage } from "./navigation.mjs";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.theme", "light");
  });
  await page.goto("/#/about", { waitUntil: "networkidle" });
  await expect(page.locator('.page-surface[data-page="about"] h2').first()).toBeVisible();
});

test("the phone toolbar keeps the full app name and reachable actions", async ({ page }) => {
  const title = page.locator(".mn-brand-copy h1");
  expect(await title.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await expect(page.getByRole("button", { name: "快速跳转", exact: true })).toBeInViewport();
  await page.getByRole("button", { name: "打开系统工具", exact: true }).click();
  const sheet = page.getByRole("dialog", { name: "系统工具", exact: true });
  await expect(sheet).toBeVisible();
  await expect(sheet.getByRole("button", { name: "刷新面板", exact: true })).toBeInViewport();
});

test("changing pages after scrolling opens the destination at its heading", async ({ page }) => {
  const navigate = async (tab) => {
    await navigateToPage(page, tab);
    await expect(page.locator(`.page-surface[data-page="${tab}"] h2`).first()).toBeVisible();
  };
  // Cache both long pages first; an empty lazy-loading shell can hide this bug.
  await navigate("control");
  await navigate("about");
  // The phone overview now folds its longer guidance; expand real content
  // before asserting that navigation resets a meaningfully scrolled page.
  const guide = page.locator(".mn-path-guide");
  await guide.locator("summary").click();
  await expect(guide).toHaveAttribute("open", "");
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(100);

  await navigate("control");
  await expect(page.locator('.page-surface[data-page="control"] h2').first()).toBeInViewport({ ratio: 1 });
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
});

for (const tab of ["webui", "output"]) {
  test(`a direct ${tab} link keeps the selected section label fully visible`, async ({ page }, testInfo) => {
    // A hash-only navigation would exercise the normal setTab path instead of mounting a deep link.
    await page.goto("about:blank");
    await page.goto(`/#/${tab}`, { waitUntil: "networkidle" });
    await expect(page.locator(`.page-surface[data-page="${tab}"] h2`).first()).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    const desktop = await page.locator(".desktop-rail").isVisible();
    const assertDesktopNavigation = async () => {
      await expect(page.locator(`.desktop-rail [data-tab="${tab}"][aria-current="page"]`)).toBeInViewport({ ratio: 1 });
      await expect(page.locator(".page-surface")).toHaveAttribute("data-page", tab);
      expect(await page.evaluate(() => window.scrollY)).toBe(0);
    };
    if (desktop) {
      await assertDesktopNavigation();
    } else {
      await expect(page.locator('.mobile-nav [aria-haspopup="dialog"]')).toHaveAttribute("aria-current", "page");
    }
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
    await page.keyboard.press("Tab");
    await expect(page.locator(".mn-skip-link")).toBeFocused();

    if (desktop) {
      await page.setViewportSize({ ...page.viewportSize(), height: 640 });
      await assertDesktopNavigation();
      await page.locator(".mn-language-header select").selectOption("ru");
      await expect(page.locator("html")).toHaveAttribute("lang", "ru");
      await assertDesktopNavigation();
    }
    await page.screenshot({ path: testInfo.outputPath(`navigation-${tab}.png`) });
  });
}
