import { navigateToPage } from "./navigation.mjs";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
  });
});

test("proxy groups are one tap away from the overview", async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await navigateToPage(page, "proxies");
  await expect(page).toHaveURL(/#\/proxies$/);
  await expect(page.getByRole("heading", { name: "节点与代理组", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "代理组", exact: true })).toBeVisible();
});

test("the overview shortcut lets a translated choice submit raw selector and outbound tags", async ({ page }) => {
  await page.addInitScript(() => {
    window.__proxyCommands = [];
    let current = "proxy";
    window.ksu = {
      spawn(command, _args, _options, callbackName) {
        setTimeout(() => {
          const callback = window[callbackName];
          let output = "fixture.unsupported_command";
          let errno = 1;
          if (command.includes("api proxies")) {
            output = JSON.stringify({ proxies: {
              "google-proxy": { type: "Selector", now: current, all: ["proxy", "direct"] },
            } });
            errno = 0;
          } else if (command.includes("api select")) {
            window.__proxyCommands.push(command);
            current = "direct";
            output = "fixture.selected";
            errno = 0;
          }
          callback.stdout.emit("data", output);
          callback.emit("exit", errno);
        }, 0);
      },
    };
  });
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("navigation", { name: "常用入口" }).getByRole("button", { name: "切换节点", exact: true }).click();
  await expect(page).toHaveURL(/#\/proxies$/);
  await expect(page.getByRole("heading", { name: "Google 服务", exact: true })).toBeVisible();
  await page.getByPlaceholder("搜索代理组或节点").fill("直连");
  await page.getByRole("button", { name: "直连 (direct)", exact: true }).click();
  await page.getByRole("button", { name: "确认切换", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.__proxyCommands.length)).toBe(1);
  const command = await page.evaluate(() => window.__proxyCommands[0]);
  expect(command).toContain("google-proxy");
  expect(command).toContain("direct");
  expect(command).not.toMatch(/Google 服务|直连/);
  await expect(page.getByRole("button", { name: "直连 (direct) 已选择", exact: true })).toHaveAttribute("aria-pressed", "true");
});
