import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import ts from './node_modules/typescript/lib/typescript.js';
import { computed, effectScope, nextTick, ref, reactive, watch, watchEffect } from 'vue';
import { parseTailscaleControl, transitionConfirmed } from './src/components/pages/tailscaleControl.ts';
const code = readFileSync(new URL('./src/components/pages/TailscaleControls.vue', import.meta.url), 'utf8')
 .match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import[\s\S]*?;\s*$/gm,'');
const compiled=ts.transpileModule(code,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const initial={enabled:true,resumable:false,logout_pending:false,local_identity:true,core:'running',revision:'a'.repeat(64)};
const tick=()=>new Promise(r=>setImmediate(r));
const settle=async()=>{await tick();await nextTick();await tick();await nextTick();};
const response=data=>({ok:true,stdout:JSON.stringify({schema:1,ok:true,command:'tailscale.status',data})});
function deferred(){let resolve;return {promise:new Promise(r=>resolve=r),resolve:value=>resolve(value)};}
function controls(t,options={}) {
 const calls=[],events=[],hooks={}; let backend={...initial,...options.backend};
 const state=reactive({busy:Boolean(options.busy),hasKsu:true}),externalDisabled=ref(false),scope=effectScope();
 const props=reactive({disabled:false,online:true,hostname:'phone',refreshKey:''});
 // The page passes its global busy gate to the child. Keep Vue's real watcher
 // scheduling so a status read cannot accidentally schedule itself forever.
 scope.run(()=>watchEffect(()=>{props.disabled=state.busy||externalDisabled.value;}));
 const deps={computed,ref,watch,defineProps:()=>props,defineEmits:()=>(name,value)=>events.push([name,value]),
  ...Object.fromEntries(['onMounted','onActivated','onDeactivated','onUnmounted'].map(name=>[name,fn=>hooks[name]=fn])),
  t:key=>key,parseTailscaleControl,transitionConfirmed,
  useMagicNet:()=>({state,shellQuote:s=>s,openExternal:async()=>{},refreshStatus:async()=>{},
   runPrivateCli:async command=>{calls.push(command);
    state.busy=true;
    try {
     await tick();
     if(command==='--json tailscale status') return options.read?await options.read():response(backend);
     if(options.mutate) await options.mutate();
     const action=command.split(' ')[1];
     if(options.fail) return {ok:false,stdout:'private diagnostic, not UI text'};
     backend={...backend,enabled:action==='enable',resumable:action==='disable',local_identity:action!=='logout',logout_pending:false};
     return {ok:true,stdout:''};
    } finally {state.busy=false;}
   }})};
 const make=new Function(...Object.keys(deps),compiled+'\nreturn {read,change,control,loading,locked,pending,confirmLogout,message,failed};');
 const instance=scope.run(()=>make(...Object.values(deps)));
 t.after(()=>{hooks.onUnmounted();scope.stop();});
 return {...instance,calls,events,hooks,props,state,externalDisabled};
}
test('logout needs explicit confirmation and cannot be accidentally submitted twice',async t=>{
 let resolve; const gate=new Promise(r=>resolve=r),p=controls(t,{mutate:()=>gate});
 await p.read(); p.calls.length=0; await p.change('logout'); assert.deepEqual(p.calls,[]);
 p.confirmLogout.value=true; const work=p.change('logout'); await p.change('logout');
 assert.equal(p.pending.value,true); assert.equal(p.calls.length,1); resolve(); await work;
 assert.equal(p.control.value.local_identity,false); assert.equal(p.failed.value,false);
 assert.equal(p.calls.filter(c=>c.startsWith('tailscale logout')).length,1);
});
test('disable preserves the reported identity and does not claim logout',async t=>{
 const p=controls(t); await p.read(); await p.change('disable');
 assert.equal(p.control.value.enabled,false); assert.equal(p.control.value.resumable,true);
 assert.match(p.message.value,/登录信息保留/);
});
test('failed writes are not reported as success and private diagnostics are not displayed',async t=>{
 const p=controls(t,{fail:true}); await p.read(); await p.change('disable');
 assert.equal(p.failed.value,true); assert.equal(p.control.value.enabled,true);
 assert.ok(!p.message.value.includes('private diagnostic'));
});
test('incomplete logout blocks resume, and external busy state blocks destructive writes',async t=>{
 const p=controls(t,{backend:{enabled:false,resumable:true,logout_pending:true}}); await p.read(); p.calls.length=0;
 await p.change('enable'); assert.equal(p.calls.length,0);
 p.confirmLogout.value=true;p.externalDisabled.value=true;await nextTick();await p.change('logout');assert.equal(p.calls.length,0);
});
test('completion after navigation cannot publish a stale status or reload the old page',async t=>{
 let resolve; const gate=new Promise(r=>resolve=r),p=controls(t,{mutate:()=>gate}); await p.read(); p.events.length=0;
 const work=p.change('disable');p.hooks.onDeactivated();resolve();await work;await tick();
 assert.equal(p.control.value.enabled,true);assert.equal(p.pending.value,false);
 assert.ok(!p.events.some(([name])=>name==='changed'||name==='observed'));
});

test('mount and initial activation perform one status read and leave controls usable',async t=>{
 const p=controls(t);p.hooks.onMounted();p.hooks.onActivated();await settle();
 assert.deepEqual(p.calls,['--json tailscale status']);
 assert.equal(p.control.value.enabled,true);assert.equal(p.loading.value,false);
 assert.equal(p.state.busy,false);assert.equal(p.locked.value,false);
 await settle();assert.equal(p.calls.length,1);
});
test('a failed status read settles without automatic retries and can be retried explicitly',async t=>{
 let fail=true;const p=controls(t,{read:()=>fail?{ok:false,stdout:''}:response(initial)});
 p.hooks.onMounted();await settle();
 assert.equal(p.calls.length,1);assert.equal(p.control.value,null);
 assert.equal(p.loading.value,false);assert.equal(p.locked.value,false);
 fail=false;await p.read();await settle();
 assert.equal(p.calls.length,2);assert.equal(p.control.value.enabled,true);
});
test('an initial read waits for external busy work and later busy changes do not reread',async t=>{
 const p=controls(t,{busy:true});p.hooks.onMounted();p.hooks.onActivated();await nextTick();
 assert.equal(p.calls.length,0);
 p.state.busy=false;await settle();
 assert.equal(p.calls.length,1);assert.equal(p.locked.value,false);
 p.state.busy=true;await nextTick();p.state.busy=false;await settle();
 assert.equal(p.calls.length,1);
});
test('a changed endpoint revision requests a fresh status read',async t=>{
 const p=controls(t);await p.read();await nextTick();
 p.props.refreshKey='updated-endpoint';await settle();
 assert.equal(p.calls.length,2);assert.equal(p.locked.value,false);
});
test('endpoint changes during a status read coalesce into one latest read without publishing the obsolete result',async t=>{
 const first=deferred(),latest=deferred();let reads=0;
 const p=controls(t,{read:()=>++reads===1?first.promise:latest.promise});
 const work=p.read();await nextTick();
 p.props.refreshKey='intermediate';await nextTick();
 p.props.refreshKey='latest';await nextTick();
 assert.equal(p.calls.length,1);
 first.resolve(response(initial));await work;await settle();
 assert.equal(p.calls.length,2);assert.equal(p.events.some(([name])=>name==='observed'),false);
 latest.resolve(response({...initial,revision:'b'.repeat(64),enabled:false,resumable:true}));await settle();
 assert.equal(p.control.value.revision,'b'.repeat(64));assert.equal(p.control.value.enabled,false);
 assert.equal(p.calls.length,2);assert.equal(p.locked.value,false);
});
