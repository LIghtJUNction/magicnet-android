import {createRequire} from 'node:module';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const require=createRequire(import.meta.url);
const {chromium}=require('/workspace/scratch/16b295519d04/tools/playwright-1.56.1/node_modules/playwright');
const base=process.env.MAGICNET_WEBUI_URL||'http://127.0.0.1:18731';
const out=new URL('../test-artifacts/',import.meta.url);fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({headless:true});
const pages=['overview','paths','apps','nodes','groups','block','chain','subscriptions','tailscale','config','panel','health','terminal','tools','output'];
const sizes=[[320,760],[360,800],[390,844],[430,900],[844,390],[1280,900]];
const failures=[],samples=[];let checked=0;
for(const locale of ['zh-CN','en','ru'])for(const theme of ['light','dark'])for(const [width,height] of sizes){
 const context=await browser.newContext({viewport:{width,height},locale,reducedMotion:'reduce'});
 await context.addInitScript(({locale,theme})=>{localStorage.setItem('magicnet.webui.locale',locale);localStorage.setItem('magicnet.webui.theme',theme);},{locale,theme});
 const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.locator('main h1').waitFor({state:'visible'});
 for(const route of pages){
  await page.evaluate(route=>location.hash=route,route);await page.waitForFunction(route=>document.querySelector('main')?.dataset.route===route&&location.hash==='#'+route,route);
  const overflow=await page.evaluate(()=>({body:document.documentElement.scrollWidth,viewport:innerWidth,heading:document.querySelector('main h1')?.textContent,lang:document.documentElement.lang}));
  if(overflow.body>width+1)failures.push({locale,theme,width,height,route,kind:'layout_overflow',...overflow});
  if(overflow.lang!==locale)failures.push({locale,theme,width,height,route,kind:'language_mismatch'});
  checked++;
 }
 if(errors.length)failures.push({locale,theme,width,height,errors});
 if(locale==='zh-CN'&&theme==='light'&&[320,390,1280].includes(width)){
  await page.evaluate(()=>location.hash='subscriptions');await page.waitForFunction(()=>document.querySelector('main')?.dataset.route==='subscriptions');await page.screenshot({path:new URL(`subscriptions-${width}.png`,out).pathname,fullPage:true});
  if(width===390){await page.evaluate(()=>location.hash='overview');await page.waitForFunction(()=>document.querySelector('main')?.dataset.route==='overview');await page.screenshot({path:new URL('overview-390.png',out).pathname,fullPage:true});}
 }
 await context.close();
}
// Verify keyboard navigation, modal cancellation, and in-memory drafts.
const context=await browser.newContext({viewport:{width:390,height:844},locale:'zh-CN'});const p=await context.newPage();await p.goto(base+'/#subscriptions');
await p.locator('#subscription-urls').fill('https://EXAMPLE.invalid:443/Feed?x=%2f&x=a+b#note');
await p.keyboard.press('Control+k');await p.locator('#palette-query').waitFor({state:'visible'});await p.keyboard.press('Escape');
assert.equal(await p.locator('#subscription-urls').evaluate(el=>document.activeElement===el),true);
await p.evaluate(()=>location.hash='config');await p.waitForTimeout(20);await p.evaluate(()=>location.hash='subscriptions');await p.waitForTimeout(20);
assert.equal(await p.locator('#subscription-urls').inputValue(),'https://EXAMPLE.invalid:443/Feed?x=%2f&x=a+b#note');
const before=await p.locator('#subscription-urls').inputValue();await p.locator('#subscription-urls').press('/');assert.equal((await p.locator('#subscription-urls').inputValue()).length,before.length+1);assert.equal(await p.locator('dialog[open]').count(),0);
await context.close();
for(const [width,height]of [[390,844],[1280,900]]){
 for(let i=0;i<8;i++){
  const c=await browser.newContext({viewport:{width,height},locale:'zh-CN',reducedMotion:'reduce'});const p=await c.newPage();await p.goto(base);await p.locator('.instrument').waitFor({state:'visible'});const ms=await p.evaluate(()=>performance.now());if(i)samples.push({width,height,ms});await c.close();
 }
}
await browser.close();
const report={environment:{browser:'Chromium 141 / Playwright 1.56.1',native:false,server:base,networkThrottle:false,cpuThrottle:false,reducedMotion:true,hostCJKFont:'Noto Sans CJK SC 2.004 installed only in the test process; product uses system fonts'},checked,failures,samples,claim:'Host preview and browser interactions only; no Android bridge or real service traffic.'};
fs.writeFileSync(new URL('browser-report.json',out),JSON.stringify(report,null,2));console.log(JSON.stringify({checked,failures,samples}));if(failures.length)process.exitCode=1;
