import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeSource,sourcePreview,Draft,sourceEditorVisible,usageRows,validateSubscription,parseArgv,normalizeFilters} from '../model.js';
import {OutputCollector,envelope,Bridge,privatePayload} from '../bridge.js';

test('URL canonical identity preserves signed query bytes and source ordering',()=>{
  assert.equal(normalizeSource('HTTPS://EXAMPLE.invalid:443/Feed?x=%2f&x=%2F&x=a+b#note'),'https://example.invalid/Feed?x=%2f&x=%2F&x=a+b');
  assert.equal(normalizeSource('https://example.invalid'),'https://example.invalid/');
  assert.equal(normalizeSource('https://example.invalid/路径?值=语言'),'https://example.invalid/%E8%B7%AF%E5%BE%84?%E5%80%BC=%E8%AF%AD%E8%A8%80');
  const p=sourcePreview('HTTPS://A.example.invalid:443#one\rhttps://a.example.invalid/#two\r\nhttps://a.example.invalid/sub?x=1&x=2\nhttps://a.example.invalid/sub?x=2&x=1');
  assert.equal(p.unique.length,3);assert.equal(p.duplicates,1);assert.equal(p.fragments,2);
});
test('six or partially invalid sources never become a truncated valid batch',()=>{
  const text=Array.from({length:6},(_,i)=>'https://example.invalid/'+i).join('\n');
  const p=sourcePreview(text);assert.equal(p.unique.length,6);assert.equal(p.canSave,false);assert.equal(p.overLimit,1);
  for(const bad of ['http://x.invalid','https://u:p@x.invalid','https://a.invalid/path with space','https://x.invalid/%xx','https://x.invalid\\evil'])assert.equal(sourcePreview('https://good.invalid\n'+bad).canSave,false);
});
test('draft C survives acceptance of submitted B',()=>{
  const d=new Draft();d.accept('A');d.edit('B');const b=d.snapshot();d.edit('C');d.accept('B',b);assert.equal(d.value,'C');assert.equal(d.baseline,'B');assert.equal(d.dirty,true);d.reset();assert.equal(d.value,'B');
});
test('a new dirty draft stays visible when an earlier first-source import commits',()=>{
  const d=new Draft();d.accept('');assert.equal(sourceEditorVisible(d,0,false),true);
  d.edit('B');const submitted=d.snapshot();d.edit('C');d.accept('',submitted);
  assert.equal(d.value,'C');assert.equal(sourceEditorVisible(d,1,false),true);
  assert.equal(sourceEditorVisible(d,null,false),true);
  d.reset();assert.equal(sourceEditorVisible(d,1,false),false);
  assert.equal(sourceEditorVisible(d,1,true),true);
});
test('usage is keyed by full URL identity and missing records do not remove sources',async()=>{
  const urls=['https://example.invalid/feed?t=one','https://example.invalid/feed?t=two'];
  const id=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(urls[0]))).toString('hex');
  const data={source:{mode:'remote_url'},configuration:{sing_box_urls:urls},source_usage:[{id,index:1,hostname:'example.invalid',state:'fresh',upload_bytes:10,download_bytes:20,total_bytes:100,expire_epoch:0}],last:{result:'success'},update:{owner:'none',transaction_pending:false}};
  const rows=await usageRows(data);assert.equal(rows.length,2);assert.equal(rows[0].used,30);assert.equal(rows[1].used,null);assert.equal(rows[1].state,'unknown');assert.equal(rows[0].expires,null);
  data.configuration.sing_box_urls.reverse();const reordered=await usageRows(data);assert(reordered.every(r=>r.state==='unknown'));
});
test('machine envelopes reject nonzero, extra JSON and mismatched command',()=>{
  const good={exit_code:0,stdout:JSON.stringify({schema:1,ok:true,command:'sub.status',data:{}})};
  assert.deepEqual(envelope(good,'sub.status'),{});assert.throws(()=>envelope({...good,stdout:good.stdout+'\n{}'},'sub.status'));assert.throws(()=>envelope(good,'sub.inspect'));assert.throws(()=>envelope({...good,exit_code:1},'sub.status'));
});
test('collector counts empty events and combines both output streams',()=>{
  const c=new OutputCollector();for(let n=0;n<65537;n++)c.add('stdout','');assert.equal(c.overflow,true);assert.equal(c.stdout,'');
  const d=new OutputCollector();d.add('stdout','x'.repeat(4194304));d.add('stderr','x'.repeat(4194305));assert.equal(d.overflow,true);assert.equal(d.stdout,'');assert.equal(d.stderr,'');
});
test('unknown subscription owner cannot masquerade as running success',()=>{
  const value={source:{mode:'remote_url',configured_count:1},update:{owner:'unknown',running:true,lock_present:true,transaction_pending:false},last:{phase:'complete',result:'success',batch:null},configuration:{sing_box_urls:['https://example.invalid/'],user_agent:'',filters:[]},source_usage:[]};
  assert.throws(()=>validateSubscription(value,true,true));value.update.running=null;assert.equal(validateSubscription(value,true,true),value);
});
test('terminal arguments never evaluate shell expansion',()=>{
  assert.deepEqual(parseArgv('node test "constructor"'),['node','test','constructor']);
  for(const code of ['service stop; id','$(id)','api groups | cat','node use > /tmp/x'])assert.throws(()=>parseArgv(code));
});
test('filter ASCII dedup and UTF-8 limits are explicit',()=>{
  assert.deepEqual(normalizeFilters(' Free \nfree\n香港'),['Free','香港']);assert.throws(()=>normalizeFilters('字'.repeat(22)));assert.throws(()=>normalizeFilters(Array.from({length:33},(_,i)=>String(i)).join('\n')));
});
test('native timeout keeps execution slot until the real callback exits',async()=>{
  globalThis.location={hash:'',hostname:'127.0.0.1'};let callback;
  globalThis.MagicNetNative={exec:(_request,name)=>{callback=name;}};
  const bridge=new Bridge();const pending=bridge.execute(['service','start'],{write:true,timeout:5});await assert.rejects(pending,{code:'operation.timeout'});assert(bridge.writing);
  await assert.rejects(bridge.execute(['service','stop'],{write:true}),{code:'operation.busy'});
  globalThis[callback](0,'{}','');assert.equal(bridge.writing,null);assert.equal(globalThis[callback],undefined);delete globalThis.MagicNetNative;
});
test('payload bytes preserve all sources and failed append cannot apply',async()=>{
  let contents=Buffer.alloc(0),applied=0,removed=0;
  const bridge={writing:null,dispatchEvent(){},async execute(args){
    if(args[2]==='create')return{exit_code:0,stdout:'/data/adb/modules/MagicNet/.state/private/payload/subscription/'+args[4]+'\n'};
    if(args[2]==='append'){contents=Buffer.concat([contents,Buffer.from(args[5],'base64')]);return{exit_code:0,stdout:''};}
    if(args[2]==='remove'){removed++;return{exit_code:0,stdout:''};}
    applied++;return{exit_code:0,stdout:'{}'};
  }};
  const input='https://a.invalid/路径?x=%26&x=\'one\'\nhttps://a.invalid/?x=%23+two\n';await privatePayload(bridge,input,'subscription','apply-subscription');assert.equal(contents.toString('utf8'),input);assert.equal(applied,1);assert.equal(removed,1);
  bridge.execute=async args=>{if(args[2]==='create')return{exit_code:0,stdout:'/data/adb/modules/MagicNet/.state/private/payload/subscription/'+args[4]};if(args[2]==='append')return{exit_code:1,stdout:''};if(args[2]==='remove'){removed++;return{exit_code:0,stdout:''};}applied++;return{exit_code:0,stdout:''};};
  await assert.rejects(privatePayload(bridge,input,'subscription','apply-subscription'));assert.equal(applied,1);assert.equal(removed,2);
});
test('stream overflow cannot release a native writer before its exit',async()=>{
  globalThis.location={hash:'',hostname:'127.0.0.1'};let callback;
  globalThis.ksu={exec(){},spawn:(_binary,_args,_options,name)=>{callback=name;}};
  const bridge=new Bridge();const pending=bridge.execute(['sub','update','sing-box'],{write:true});
  for(let i=0;i<65537;i++)globalThis[callback].stdout.emit('data','');
  assert(bridge.writing);await assert.rejects(bridge.execute(['service','stop'],{write:true}),{code:'operation.busy'});
  globalThis[callback].emit('exit',0);await assert.rejects(pending,{code:'bridge.output_limit'});
  assert.equal(bridge.writing,null);assert.equal(globalThis[callback],undefined);delete globalThis.ksu;
});
test('a definite HTTP request rejection creates no lingering executor owner',async()=>{
  globalThis.location={hash:'',hostname:'127.0.0.1'};const original=globalThis.fetch;let calls=0;
  globalThis.fetch=async()=>{calls++;return new Response('{}',{status:409});};
  try{const bridge=new Bridge();bridge.mode='http';bridge.token='synthetic';
    await assert.rejects(bridge.execute(['service','stop'],{write:true}),{code:'bridge.request_rejected'});
    assert.equal(bridge.writing,null);assert.equal(calls,1);
  }finally{globalThis.fetch=original;}
});
