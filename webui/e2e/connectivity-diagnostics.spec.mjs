import { test, expect } from '@playwright/test';

async function mount(page) {
  await page.addInitScript(() => {
    localStorage.setItem('magicnet.webui.onboarding.v1', 'dismissed');
    window.__diagnosticFixture = { exports: 0, fail: false, commands: [] };
    window.ksu = {
      spawn(command, _args, _options, callbackName) {
        const fixture = window.__diagnosticFixture;
        fixture.commands.push(command);
        const exporting = command.includes('cli --json support export');
        const capabilities = command.includes('cli --json capabilities');
        if (exporting) fixture.exports++;
        setTimeout(() => {
          const cb = window[callbackName];
          if (!cb) return;
          const ok = capabilities || (exporting && !fixture.fail);
          const value = capabilities
            ? {schema:1,ok:true,command:'machine.capabilities',data:{commands:['support.export'],mutation_commands:['support.export']}}
            : ok
            ? {schema:1,ok:true,command:'support.export',data:{path:'/sdcard/Download/MagicNet/MagicNet-diagnostics.txt',bytes:12800}}
            : {schema:1,ok:false,command:'machine.error',error:{code:exporting ? 'support.export_failed' : 'machine.unsupported_command',message:'fixture-private-failure'}};
          cb.stdout.emit('data', JSON.stringify(value));
          cb.emit('exit', ok ? 0 : 1);
        }, exporting ? 75 : 0);
      },
    };
  });
  await page.goto('/#/health', {waitUntil:'networkidle'});
  await expect(page.locator('.page-surface')).toHaveAttribute('data-page', 'health');
  await page.evaluate(async () => {
    const {state} = (await import('/src/composables/useMagicNet.ts')).useMagicNet();
    Object.assign(state, {hasKsu:true,busy:false,phase:'idle',queueDepth:0,output:'',notice:''});
    Object.assign(state.connectivity, {status:'offline',reason:'timeout',warning:true,
      checkedAt:1234,nextCheckAt:1714,latencyMs:null,retryInSeconds:480,failures:4,
      lastAction:'refresh',actionStatus:'failed'});
  });
}

test('warning explains failed Google check and exports one complete device file', async ({page}, info) => {
  await mount(page);
  const notice = page.getByTestId('connectivity-notice');
  await expect(notice).toHaveAttribute('role', 'alert');
  await expect(notice).toContainText('⚠️ Google 连接失败');
  await expect(notice).toContainText('480 秒');
  await expect(notice).toContainText('已尝试更新订阅');
  const button = page.getByRole('button', {name:'一键导出诊断包',exact:true});
  // Immediate duplicate events must share the same in-flight export.
  await button.evaluate(button => { button.click(); button.click(); });
  await expect(page.getByTestId('diagnostics-export-result')).toContainText('/sdcard/Download/MagicNet/MagicNet-diagnostics.txt');
  expect(await page.evaluate(() => window.__diagnosticFixture.exports)).toBe(1);
  const commands = await page.evaluate(() => window.__diagnosticFixture.commands);
  expect(commands.some(command => /connectivity tick|pingtest|sub update|sing-box restart/.test(command))).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await page.screenshot({path:info.outputPath('diagnostics-export.png'),fullPage:true,timeout:20000});
});

test('export failure clears the previous file confirmation and hides raw error text', async ({page}) => {
  await mount(page);
  const button = page.getByRole('button', {name:'一键导出诊断包',exact:true});
  await button.click();
  await expect(page.getByTestId('diagnostics-export-result')).toBeVisible();
  await page.evaluate(() => { window.__diagnosticFixture.fail = true; });
  await button.click();
  await expect(page.getByTestId('diagnostics-export-result')).toHaveCount(0);
  await expect(page.locator('.page-surface')).toContainText('诊断包导出失败');
  await expect(page.locator('.page-surface')).not.toContainText('fixture-private-failure');
});

test('overview separates core readiness from Google availability and clears recovered warning', async ({page}) => {
  await mount(page);
  await page.evaluate(() => { window.location.hash = '/control'; });
  await expect(page.locator('.mn-control')).toBeVisible();
  await page.evaluate(async () => {
    const {state} = (await import('/src/composables/useMagicNet.ts')).useMagicNet();
    Object.assign(state.runtime, {singBoxState:'sing-box',singBox:'123',serviceReady:true});
    Object.assign(state.connectivity, {status:'offline',warning:true});
  });
  await expect(page.getByTestId('connectivity-notice')).toHaveAttribute('role','alert');
  await expect(page.getByTestId('connectivity-notice').getByRole('button',{name:'打开诊断',exact:true})).toBeVisible();
  await page.evaluate(async () => {
    const {state} = (await import('/src/composables/useMagicNet.ts')).useMagicNet();
    Object.assign(state.connectivity, {status:'online',warning:false,latencyMs:52,failures:0});
  });
  await expect(page.getByTestId('connectivity-notice')).toHaveAttribute('role','status');
  await expect(page.getByTestId('connectivity-notice')).toContainText('Google 连接正常');
  await expect(page.getByTestId('connectivity-notice')).not.toContainText('已尝试更新订阅');
});
