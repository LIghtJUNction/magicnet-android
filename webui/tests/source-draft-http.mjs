// Targeted regression: real compiled controller and pinned core, with only the
// delivery of an authentic successful HTTP response delayed by the browser.
import {createRequire} from 'node:module';
import {spawn, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

const require = createRequire(import.meta.url);
const {chromium} = require(process.env.MAGICNET_PLAYWRIGHT || '/workspace/scratch/16b295519d04/tools/playwright-1.56.1/node_modules/playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const reports = path.join(root, 'webui/test-artifacts');
const fixtures = path.join(root, 'module/test-artifacts');
fs.mkdirSync(reports, {recursive:true}); fs.mkdirSync(fixtures, {recursive:true});
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function deadline(promise, milliseconds, message) {
  let timer;
  try {return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),milliseconds);})]);}
  finally {clearTimeout(timer);}
}
function cli(fixture, args) {
  const result = spawnSync(path.join(fixture, 'bin/magicnet-cli'), args, {
    cwd:fixture, env:{...process.env, MAGICNET_ROOT:fixture, MAGICNET_API:'http://127.0.0.1:9'},
    encoding:'utf8', timeout:120000, maxBuffer:2*1024*1024
  });
  assert.equal(result.status,0,`CLI ${args.slice(0,3).join(' ')} failed: ${result.stderr || result.error?.message || ''}`);
  return result.stdout.trim() ? JSON.parse(result.stdout) : null;
}
async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve);});
  const port = probe.address().port;
  await new Promise(resolve=>probe.close(resolve));
  return port;
}
async function startServer(fixture) {
  const port = await freePort();
  const child = spawn(path.join(fixture, 'bin/magicnet-cli'), ['__http',`127.0.0.1:${port}`], {
    cwd:fixture, env:{...process.env, MAGICNET_ROOT:fixture, MAGICNET_API:'http://127.0.0.1:9'}, stdio:['ignore','ignore','pipe']
  });
  let privateOutput = ''; child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => {privateOutput = (privateOutput + chunk).slice(-65536);});
  const exit = new Promise(resolve=>child.once('exit',resolve));
  const stop = async () => {
    if(child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([exit,delay(3000)]);
      if(child.exitCode === null && child.signalCode === null){child.kill('SIGKILL');await exit;}
    }
    privateOutput='';
  };
  try {
    for(let attempt=0;attempt<200;attempt++) {
      assert(child.exitCode===null,'Fixture HTTP controller exited before readiness');
      const entry=privateOutput.match(/http:\/\/127\.0\.0\.1:\d+\/#session=[A-Za-z0-9_-]+/)?.[0];
      if(entry) {
        try {const response=await fetch(entry.split('#')[0]);if(response.ok)return {entry,stop};}catch{}
      }
      await delay(25);
    }
    throw new Error('Explicit fixture HTTP entry did not become ready');
  } catch(error) {await stop();throw error;}
}

const browser=await chromium.launch({headless:true});
const cases=[], failures=[], pageErrors=[];
let controller;
try {
  for(const [width,height] of [[390,844],[1280,900]]) {
    const temporary=fs.mkdtempSync(path.join(fixtures,'source-draft-'));
    const fixture=path.join(temporary,'MagicNet');
    let server,context,release=()=>{};
    try {
      fs.mkdirSync(path.join(fixture,'bin'),{recursive:true,mode:0o700});
      fs.mkdirSync(path.join(fixture,'webroot'),{mode:0o700});
      for(const name of ['magicnet-cli','sing-box'])fs.copyFileSync(path.join(root,'assets/bin/linux-amd64',name),path.join(fixture,'bin',name));
      fs.copyFileSync(path.join(root,'module/module.prop'),path.join(fixture,'module.prop'));
      fs.cpSync(path.join(root,'assets/rules'),path.join(fixture,'.config/sing-box/rules'),{recursive:true});
      for(const name of ['index.html','app.js','bridge.js','model.js','i18n.js','styles.css','icon.svg'])fs.copyFileSync(path.join(root,'webui',name),path.join(fixture,'webroot',name));
      cli(fixture,['__install']);cli(fixture,['service','stop']);
      controller=cli(fixture,['version']);
      server=await startServer(fixture);
      context=await browser.newContext({viewport:{width,height},locale:'en',reducedMotion:'reduce'});
      const page=await context.newPage();page.on('pageerror',error=>pageErrors.push(error.message));
      const requests=[];
      page.on('request',request=>{if(request.url().endsWith('/api/command'))requests.push(JSON.parse(request.postData()));});
      await page.goto(server.entry);
      await page.evaluate(async()=>{globalThis.__magicnetTest=await import('/app.js');});
      await page.waitForFunction(()=>Boolean(globalThis.__magicnetTest.bridge.capabilities));
      await page.evaluate(()=>location.hash='subscriptions');
      await page.waitForFunction(()=>globalThis.__magicnetTest.state.sources.loaded&&document.querySelector('main')?.dataset.route==='subscriptions');
      // New browser profiles receive the actual first-use explanation. Close
      // it through its visible control before interacting with the editor.
      for(const modal of await page.locator('dialog[open]').all())await modal.getByRole('button',{name:'Cancel',exact:true}).click();
      const initial=await page.evaluate(()=>({count:__magicnetTest.state.subscription.source.configured_count,explicit:__magicnetTest.state.sourcesOpen}));
      assert.deepEqual(initial,{count:0,explicit:false});
      assert(await page.locator('#subscription-urls').isVisible(),'Fresh zero-source editor was not visible');
      await page.locator('#source-editor').getByRole('button',{name:'Cancel',exact:true}).click();
      assert(await page.locator('#subscription-urls').isVisible(),'Cancelling a clean empty editor hid the first-source form');

      const draftB='https://draft-b.example.invalid/feed?canary=REPAIR_UI_B';
      const draftC='https://draft-c.example.invalid/feed?canary=REPAIR_UI_C';
      await page.locator('#subscription-urls').fill(draftB);
      const payload=JSON.stringify({outbounds:[{type:'socks',tag:'synthetic-local-repair',server:'127.0.0.1',server_port:1080}]});
      await page.locator('#subscription-file').setInputFiles({name:'synthetic-local-repair.json',mimeType:'application/json',buffer:Buffer.from(payload)});
      let received;
      const receiptReady=new Promise(resolve=>received=resolve);
      const deliveryGate=new Promise(resolve=>release=resolve);
      await page.route('**/api/command',async route=>{
        const request=route.request().postDataJSON();
        if(request.args?.slice(0,3).join(' ')==='webui payload apply-subscription-source') {
          const response=await route.fetch();
          const authentic=await response.json();
          received(authentic);await deliveryGate;
          await route.fulfill({response});
        } else await route.continue();
      });
      await page.getByRole('button',{name:'Add and enable',exact:true}).last().click();
      await page.locator('dialog[open]').getByRole('button',{name:'Confirm',exact:true}).click();
      const authentic=await deadline(receiptReady,120000,'Real import receipt timeout');
      assert.equal(authentic.exit_code,0);assert.equal(authentic.running,false);
      assert.equal(await page.evaluate(()=>__magicnetTest.state.subscription.source.configured_count),0,'Receipt reached the UI before the deliberate delivery delay');
      await page.locator('#subscription-urls').fill(draftC);
      assert.equal(await page.evaluate(()=>Boolean(__magicnetTest.state.workflow&&__magicnetTest.bridge.writing)),true);
      release();
      await page.waitForFunction(()=>{const {state,bridge}=__magicnetTest;return state.sourceOutcome==='committed'&&!state.workflow&&!bridge.writing;},null,{timeout:120000});
      const observed=await page.evaluate(()=>({count:__magicnetTest.state.subscription.source.configured_count,mode:__magicnetTest.state.subscription.source.mode,dirty:__magicnetTest.state.sources.dirty,explicit:__magicnetTest.state.sourcesOpen,baseline:__magicnetTest.state.sources.baseline,output:__magicnetTest.state.output}));
      assert.equal(observed.count,1);assert.equal(observed.mode,'local_file');assert.equal(observed.dirty,true);assert.equal(observed.explicit,false);assert.equal(observed.baseline,'');
      assert.equal(await page.locator('#subscription-urls').inputValue(),draftC);
      assert(await page.locator('#subscription-urls').isVisible(),'New dirty draft was collapsed after the older first-source import committed');
      assert.equal(await page.locator('#source-dirty .dirty.clean').count(),0);
      await page.evaluate(()=>location.hash='tools');
      await page.waitForFunction(()=>document.querySelector('main')?.dataset.route==='tools');
      await page.evaluate(()=>location.hash='subscriptions');
      await page.waitForFunction(()=>document.querySelector('main')?.dataset.route==='subscriptions');
      assert.equal(await page.locator('#subscription-urls').inputValue(),draftC);
      assert(await page.locator('#subscription-urls').isVisible(),'Navigation hid the preserved dirty draft');
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await page.evaluate(()=>scrollTo(0,0));
      await page.screenshot({path:path.join(reports,`source-draft-${width}.png`),fullPage:true});
      await page.locator('#source-editor').getByRole('button',{name:'Cancel',exact:true}).click();
      assert.equal(await page.locator('#subscription-urls').isVisible(),false);
      assert(await page.locator('#manage-sources').isVisible());
      await page.locator('#manage-sources').click();assert.equal(await page.locator('#subscription-urls').inputValue(),'');
      assert(!JSON.stringify(observed.output).includes('REPAIR_UI_'));
      const storage=await page.evaluate(()=>({local:{...localStorage},session:{...sessionStorage}}));
      assert(!JSON.stringify(storage).includes('REPAIR_UI_'));
      const chunks=requests.filter(r=>r.args.slice(0,4).join(' ')==='webui payload append subscription').map(r=>Buffer.from(r.args[5],'base64'));
      assert.equal(Buffer.concat(chunks).toString('utf8'),payload);
      const status=cli(fixture,['--json','service','status']).data;
      assert.equal(status.process.state,'stopped');
      const leftovers=path.join(fixture,'.state/private/payload/subscription');
      assert(!fs.existsSync(leftovers)||fs.readdirSync(leftovers).length===0);
      cases.push({width,height,passed:true,checks:['fresh zero-source editor visible without an explicit-open flag','authentic compiled import response delayed, without modifying its bytes','new draft edited while old invocation owns the writer','committed local source count becomes one','new draft text and dirty state preserved and visible','draft remains visible after page navigation','explicit cancel restores baseline and collapses the clean editor','complete local payload preserved and consumed','shared output and browser storage contain no draft canary','core remains stopped','no horizontal overflow'],request_count:requests.length});
    } catch(error) {
      failures.push({width,height,error:error.message});
    } finally {
      release();
      if(context)await context.close();
      if(server)await server.stop();
      fs.rmSync(temporary,{recursive:true,force:true});
    }
  }
} finally {await browser.close();}
const report={passed:failures.length===0&&pageErrors.length===0,controller,
  binary_sha256:digest(path.join(root,'assets/bin/linux-amd64/magicnet-cli')),
  ui_sha256:Object.fromEntries(['app.js','model.js'].map(name=>[name,digest(path.join(root,'webui',name))])),
  environment:'Chromium 141 / Playwright 1.56.1; actual compiled Linux controller, authenticated loopback HTTP and pinned core check; fresh synthetic module roots',
  host_cjk_font:process.env.FONTCONFIG_FILE?'Host-only font configuration supplied; product still uses system fonts':'Host font defaults',
  response_timing:'The real successful apply response is withheld until C is entered; no state or receipt projection is used.',
  network_used:'loopback only; synthetic local subscription, no provider request',device_used:false,core_started:false,cases,failures,pageErrors,cleanup:'fixture HTTP processes and temporary module roots removed'};
fs.writeFileSync(path.join(reports,'source-draft-http-report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report));
if(!report.passed)process.exitCode=1;
