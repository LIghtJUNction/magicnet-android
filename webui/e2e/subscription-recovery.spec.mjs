import { expect, test } from "@playwright/test";
import { subscriptionData } from "../machine-fixtures.mjs";

test("a failed first read protects existing subscriptions and keeps every draft through retry", async ({ page }) => {
  await page.addInitScript(data => {
    localStorage.setItem("magicnet.webui.onboarding.v1", "dismissed");
    localStorage.setItem("magicnet.webui.locale", "zh-CN");
    window.__recovery = { data, failReads: true, writes: [] };
    window.ksu = { spawn(command, _args, _options, callbackName) {
      setTimeout(() => {
        const fixture = window.__recovery;
        const callback = window[callbackName];
        if (command.includes("--json sub inspect")) {
          if (fixture.failReads) { callback.emit("exit", 1); return; }
          callback.stdout.emit("data", JSON.stringify({ schema: 1, ok: true, command: "sub.inspect", data: fixture.data }));
        } else if (/\bsub (?:clear|update-all|user-agent|filter|schedule)\b|webui payload/.test(command)) {
          fixture.writes.push(command);
        }
        callback.emit("exit", 0);
      }, 10);
    } };
  }, subscriptionData({
    configuration: { sing_box_urls: ["https://existing.example/sub"], user_agent: "device-agent", filters: ["device-filter"] },
    schedule: { interval_hours: "12", enabled: true, owner: "active", running: true, owner_valid: true },
  }));
  await page.goto("/#/subs", { waitUntil: "networkidle" });
  const notice = page.locator(".subscription-read-notice");
  await expect(notice).toHaveAttribute("data-read-status", "error");
  await expect(page.getByRole("heading", { name: "添加第一个订阅", exact: true })).toHaveCount(0);
  const retry = page.getByRole("button", { name: "重新读取订阅状态", exact: true });
  await expect(retry).toBeEnabled();
  const editor = page.getByRole("textbox", { name: "订阅链接，每行一个", exact: true });
  await editor.fill("https://draft.example/sub");
  await expect(page.getByRole("button", { name: "保存并应用", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "导入文件", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "粘贴链接", exact: true })).toBeEnabled();

  await page.getByText("订阅设置", { exact: true }).click();
  const userAgent = page.getByLabel("自定义值", { exact: true });
  await userAgent.fill("draft-agent");
  const interval = page.getByLabel("更新频率", { exact: true });
  await interval.selectOption("48");
  await page.getByLabel("自定义节点过滤关键词", { exact: true }).fill("draft-filter");
  await page.getByRole("button", { name: "添加过滤关键词", exact: true }).click();
  for (const label of ["保存 User-Agent", "保存过滤词", "保存更新设置"]) {
    await expect(page.getByRole("button", { name: label, exact: true })).toBeDisabled();
  }
  expect(await page.evaluate(() => window.__recovery.writes)).toEqual([]);

  await page.evaluate(() => { window.__recovery.failReads = false; });
  await retry.click();
  await expect(notice).toHaveCount(0);
  await expect(editor).toBeVisible();
  await expect(editor).toHaveValue("https://draft.example/sub");
  await expect(page.getByRole("button", { name: "保存并应用", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "导入文件", exact: true })).toBeEnabled();
  await expect(userAgent).toHaveValue("draft-agent");
  await expect(interval).toHaveValue("48");
  await expect(page.getByRole("button", { name: "移除过滤词 draft-filter", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "保存更新设置", exact: true })).toBeEnabled();
  for (const save of await page.getByRole("button", { name: "保存并刷新订阅", exact: true }).all()) {
    await expect(save).toBeEnabled();
  }

  await editor.fill("");
  await page.getByRole("button", { name: "移除所有来源", exact: true }).click();
  await expect(page.getByRole("button", { name: "确认移除", exact: true })).toBeVisible();
  await page.evaluate(() => { window.__recovery.failReads = true; });
  await retry.click();
  await expect(notice).toHaveAttribute("data-read-status", "error");
  await expect(page.getByRole("button", { name: "确认移除", exact: true })).toHaveCount(0);
  await expect(editor).toHaveValue("");
  await expect(page.getByRole("button", { name: "保存并应用", exact: true })).toBeDisabled();
  expect(await page.evaluate(() => window.__recovery.writes)).toEqual([]);
});
