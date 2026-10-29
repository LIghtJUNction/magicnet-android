import {Bridge, ControlError, envelope, privatePayload, base64UTF8} from './bridge.js';
import {Draft, sourceEditorVisible, sourcePreview, normalizeSource, usageRows, validateSubscription, utf8Length, normalizeFilters, validateUserAgent, parseArgv} from './model.js';
import {t,locale,setLocale,translate} from './i18n.js';

const bridge = new Bridge();
const pages = [
  ['overview','run'],['paths','routing'],['apps','routing'],['nodes','routing'],['block','routing'],['chain','routing'],
  ['subscriptions','configure'],['tailscale','configure'],['config','configure'],['panel','run'],['health','diagnose'],['terminal','diagnose'],['tools','diagnose'],['output','diagnose']
];
const state = {
  route:'overview', snapshots:new Map(), errors:new Map(), sequences:new Map(), output:[], workflow:null,
  sources:new Draft(), ua:new Draft(), filters:new Draft(), config:new Draft(), override:new Draft('{}'), repository:new Draft('{}'),
  subscription:null, usage:[], sourcePreview:null, sourcesOpen:false, localFile:null, frozen:null, sourceOutcome:null,
  routing:{schema:1,rules:[],outbounds:[]}, routingRevision:0, previewRevision:-1, overrideRevision:null, routingTargets:[],
  apps:[], selectedApps:new Set(), appQuery:'', nodeQuery:'', proxies:new Map(), groups:new Map(), delays:new Map(),
  terminalArgs:'--json service status', terminalOutput:'', privateOutput:'', configTab:'editor', panelVisible:false,
  networkCandidates:null, reviewedCandidate:null, lastRead:new Map()
};

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key,value] of Object.entries(attrs)) {
    if (key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(),event=>{
      try { const result=value(event); if(result?.catch)result.catch(error=>toast('failed','error',{code:safeCode(error)})); }
      catch(error){toast('failed','error',{code:safeCode(error)});}
    });
    else if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key === 'value') el.value = value;
    else if (key === 'checked') el.checked = value;
    else if (value !== false && value !== null && value !== undefined) el.setAttribute(key,value === true ? '' : value);
  }
  for (const child of children.flat(3)) if (child !== null && child !== undefined && child !== false) el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return el;
}
function tx(key, params = {}) { return h('span',{'data-i18n':key,'data-params':JSON.stringify(params)},t(key,params)); }
function button(key, onClick, style = '', disabled = false) { return h('button',{type:'button',class:style,disabled,onClick},tx(key)); }
function field(key, input, help = null) {
  if (!input.id) input.id = 'f-' + crypto.getRandomValues(new Uint32Array(1))[0].toString(36);
  return h('div',{class:'field'},h('label',{for:input.id},tx(key)),input,help ? h('small',{},tx(help)) : null);
}
function input(id, value = '', attrs = {}) {return h('input',{id,value,...attrs});}
function select(id, choices, value, onChange = null) {
  const el = h('select',{id,...(onChange ? {onChange} : {})});
  choices.forEach(choice => {const [val,key] = Array.isArray(choice) ? choice : [choice,choice]; el.append(h('option',{value:val},tx(key)));});
  el.value = String(value ?? choices[0]?.[0] ?? choices[0]); return el;
}
function section(key,...children) {return h('section',{class:'section'},h('h2',{},tx(key)),...children);}
function notice(key,type='warning',params={}) {return h('div',{class:'notice '+type},tx(key,params));}
function safeCode(error) {return typeof error?.code === 'string' && /^[a-zA-Z0-9_.-]{1,100}$/.test(error.code) ? error.code : 'operation.failed';}
function toast(key,type='',params={}) {const node = notice(key,type,params);document.getElementById('notices').append(node);setTimeout(()=>node.remove(),8000);}
function record(label,code,exitCode=null) {state.output.unshift({time:new Date().toISOString(),label,code,exit_code:exitCode,language:locale});state.output=state.output.slice(0,100);}
function known(value) {return value === null || value === undefined ? t('unknown') : typeof value === 'object' ? JSON.stringify(value) : String(value);}
function rawDetails(data) {return h('details',{},h('summary',{},tx('rawState')),h('pre',{class:'snapshot'},data ? JSON.stringify(data,null,2) : t('noData')));}
function viewStatus(key) {const data=state.snapshots.get(key);return [state.errors.has(key) ? notice('failed','error',{code:state.errors.get(key)}) : null,rawDetails(data)];}
function isLive() {return Boolean(bridge.capabilities);}
function hasFeature(name) {return bridge.capabilities?.features?.includes(name);}
function readOnlyButtons(container) {if(!isLive()) container.querySelectorAll('[data-device-action]').forEach(x=>x.disabled=true);}

function dialog(title,body,{accept='confirm',danger=false,onlyClose=false}={}) {
  return new Promise(resolve=>{
    const previous=document.activeElement;
    const modal=h('dialog',{'aria-labelledby':'dialog-title-'+Date.now()});
    const titleNode=h('h2',{id:modal.getAttribute('aria-labelledby'),class:'dialog-title'},tx(title));
    const finish=value=>{modal.close();modal.remove();if(previous?.isConnected && !previous.closest('[hidden]'))previous.focus();else document.getElementById('main')?.focus();resolve(value);};
    modal.append(titleNode,body,h('div',{class:'dialog-actions'},button(onlyClose?'close':'cancel',()=>finish(false)),!onlyClose?button(accept,()=>finish(true),danger?'danger':'primary'):null));
    modal.addEventListener('cancel',event=>{event.preventDefault();finish(false);});
    document.getElementById('dialogs').append(modal);modal.showModal();
    // Safe default for interruptive actions is cancellation.
    modal.querySelector('.dialog-actions button')?.focus();
  });
}
async function confirmRisk(key='risk') {return dialog('confirm',h('p',{},tx(key)),{danger:true});}
async function workflow(label, fn, {confirm=false}={}) {
  if (!isLive()) {toast('preview');return null;}
  if(state.workflow || bridge.writing) {toast('busy');return null;}
  if(confirm && !await confirmRisk(typeof confirm === 'string'?confirm:'risk'))return null;
  const owner={label,start:Date.now(),state:'running'};state.workflow=owner;updateOperation();
  try {
    const value=await fn();record(label,'none',0);return value;
  } catch(error) {
    const code=safeCode(error);record(label,code,error?.exit_code ?? null);
    if(error?.running || bridge.writing){owner.state='unknown';toast('background','warning');}
    else toast('failed','error',{code});
    return null;
  } finally {
    if(state.workflow===owner && !bridge.writing)state.workflow=null;
    updateOperation();
  }
}
function checkExit(result) {
  if(!result || result.exit_code!==0) {
    let code='command.failed';
    try {const data=JSON.parse(result.stdout);if(/^[a-z0-9_.-]{1,100}$/i.test(data.error?.code))code=data.error.code;}catch{}
    throw new ControlError(code,{exit_code:result?.exit_code});
  }
  return result;
}
async function command(args, options={}) {return checkExit(await bridge.execute(args,{write:true,label:args.slice(0,2).join('.'),...options}));}
async function action(args,{confirm=false,after=null,label=null}={}) {
  return workflow(label||args.slice(0,2).join('.'),async()=>{
    const result=await command(args);toast('finished');if(after)await after();return result;
  },{confirm});
}
async function readMachine(args,name,{privateRead=false,render=true}={}) {
  if(!isLive())return null;
  const sequence=(state.sequences.get(name)||0)+1;state.sequences.set(name,sequence);
  try {
    const data=await bridge.machine(args,name,{privateRead,label:name});
    if(state.sequences.get(name)!==sequence)return null;
    if(!privateRead)state.snapshots.set(name,data);
    state.errors.delete(name);state.lastRead.set(name,Date.now());
    if(render)renderPage();return data;
  } catch(error) {
    if(state.sequences.get(name)===sequence){state.snapshots.delete(name);state.errors.set(name,safeCode(error));if(render)renderPage();}
    throw error;
  }
}
async function readHuman(args,{privateRead=false}={}) {
  if(!isLive())throw new ControlError('bridge.preview');
  const result=checkExit(await bridge.execute(args,{privateRead,label:args.slice(0,2).join('.')}));
  try {return JSON.parse(result.stdout);}catch{return result.stdout;}
}
async function refreshOverview() {
  await Promise.allSettled([
    readMachine(['service','status'],'service.status',{render:false}),readMachine(['transparent','status'],'transparent.status',{render:false}),
    readMachine(['sub','status'],'sub.status',{render:false}),readMachine(['hotspot','status'],'hotspot.status',{render:false})
  ]);renderPage();
}

function navLinks() {
  const nav=h('nav',{'aria-label':t('menu')});
  for(const group of ['run','routing','configure','diagnose']) {
    nav.append(h('div',{class:'nav-group'},h('div',{class:'nav-title'},tx(group)),pages.filter(([,g])=>g===group).map(([id])=>
      h('a',{class:'nav-link',href:'#'+id,'aria-current':state.route===id||state.route==='groups'&&id==='nodes'?'page':null},tx(id==='nodes'?'nodeGroups':id)))));
  }
  return nav;
}
function preferences() {
  let theme='system';try{theme=localStorage.getItem('magicnet.webui.theme')||'system';}catch{}
  const langs=select('language',[['zh-CN','中文'],['en','English'],['ru','Русский']],locale,e=>setLocale(e.target.value));langs.setAttribute('aria-label',t('language'));langs.dataset.i18nLabel='language';
  const themes=select('theme',['system','light','dark'],theme,e=>{
    document.documentElement.dataset.theme=e.target.value;try{localStorage.setItem('magicnet.webui.theme',e.target.value);}catch{}
  });themes.setAttribute('aria-label',t('theme'));themes.dataset.i18nLabel='theme';
  document.documentElement.dataset.theme=theme;
  return h('div',{class:'compact-select'},langs,themes);
}
function renderShell() {
  const brand=()=>h('img',{src:'icon.svg',alt:'',width:36,height:36});
  document.getElementById('app').replaceChildren(h('div',{class:'shell'},
    h('aside',{class:'rail'},h('div',{class:'brand'},brand(),h('div',{},'MagicNet',h('small',{},tx('instrument')))),navLinks(),h('div',{class:'rail-tools'},preferences())),
    h('div',{class:'workspace'},h('header',{class:'topbar'},h('div',{class:'wordmark'},brand(),'MagicNet'),
      h('div',{class:'status',id:'connection-state'},tx(isLive()?'connected':'preview')),
      h('div',{class:'topbar-right'},button('menu',openNavigation,'mobile-menu quiet'),h('button',{class:'search-button',onClick:openPalette},tx('search'),h('kbd',{},'⌘ K')))),
      h('main',{id:'main',tabindex:-1}),h('div',{id:'operation',class:'operation',hidden:true}))));
  renderPage();
}
function openNavigation() {
  const content=h('div',{},h('div',{class:'menu-options'},navLinks()),preferences());
  content.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>content.closest('dialog')?.querySelector('.dialog-actions button')?.click()));
  dialog('menu',content,{onlyClose:true});
}
function openPalette() {
  const previous=document.activeElement;
  const list=h('div',{class:'palette-list'});
  const query=input('palette-query','',{'data-i18n-placeholder':'searchPages',placeholder:t('searchPages'),autocomplete:'off'});
  const all=[...pages.map(([id])=>[id,id]),['groups','groups']];
  const update=()=>{
    list.replaceChildren(...all.filter(([id,key])=>(id+' '+t(key)).toLowerCase().includes(query.value.toLowerCase())).map(([id,key])=>button(key,()=>{location.hash=id;modal.querySelector('.dialog-actions button').click();})));
    if(!list.children.length)list.append(h('p',{class:'empty'},tx('noMatches')));
  };
  query.addEventListener('input',update);update();
  const content=h('div',{},field('search',query),list);dialog('search',content,{onlyClose:true});
  const modal=content.closest('dialog');query.focus();
  query.addEventListener('keydown',event=>{if(event.key==='ArrowDown'){event.preventDefault();list.querySelector('button')?.focus();}});
  list.addEventListener('keydown',event=>{const items=[...list.querySelectorAll('button')],index=items.indexOf(document.activeElement);if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();items[(index+(event.key==='ArrowDown'?1:-1)+items.length)%items.length]?.focus();}});
}
function updateOperation() {
  const el=document.getElementById('operation');if(!el)return;
  const owner=state.workflow||bridge.writing;el.hidden=!owner;
  if(owner)el.replaceChildren(h('strong',{},tx(owner.state==='unknown'?'background':'busy')),h('span',{},owner.label||'operation'),tx('elapsed',{seconds:Math.floor((Date.now()-owner.start)/1000)}));
  const status=document.getElementById('connection-state');if(status)status.replaceChildren(tx(isLive()?'connected':'preview'));
}
async function connect() {
  try {
    await bridge.connect();updateOperation();await refreshOverview();
    const sub=state.snapshots.get('sub.status');
    if(sub?.source?.configured_count===0)onboarding();
    await enterPage();
  } catch(error){toast('failed','error',{code:safeCode(error)});renderPage();}
}
function onboarding() {dialog('onboardingTitle',h('p',{},tx('onboardingBody')),{accept:'importSources'}).then(ok=>{if(ok)location.hash='subscriptions';});}
function renderPage() {
  const main=document.getElementById('main');if(!main)return;
  const focused=document.activeElement,focusID=focused?.id,start=focused?.selectionStart,end=focused?.selectionEnd;
  const route=state.route;
  main.dataset.route=route;
  const title=route==='groups'?'groups':route;
  const head=h('div',{class:'page-heading'},h('div',{},h('div',{class:'eyebrow'},'MAGICNET / '+String((pages.findIndex(([p])=>p===route)+1)||4).padStart(2,'0')),h('h1',{},tx(title))),
    route!=='output' ? button(isLive()?'refresh':'connect',()=>isLive()?enterPage():connect()) : null);
  const renderers={overview:overviewPage,paths:pathsPage,apps:appsPage,nodes:nodesPage,groups:nodesPage,block:blockPage,chain:chainPage,subscriptions:subscriptionsPage,tailscale:tailscalePage,config:configPage,panel:panelPage,health:healthPage,terminal:terminalPage,tools:toolsPage,output:outputPage};
  main.replaceChildren(head,!isLive()?h('div',{class:'notice'},tx('preview'),h('p',{},tx('connectionHelp'))):h('span'),(renderers[route]||overviewPage)());
  document.querySelectorAll('.rail .nav-link').forEach(link=>{if(link.hash==='#'+route || route==='groups'&&link.hash==='#nodes')link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');});
  translate(main);
  if(focusID){const replacement=document.getElementById(focusID);if(replacement && replacement!==focused){replacement.focus({preventScroll:true});if(typeof start==='number' && replacement.setSelectionRange){try{replacement.setSelectionRange(start,end);}catch{}}}}
}
function overviewPage() {
  const service=state.snapshots.get('service.status'),transparent=state.snapshots.get('transparent.status');
  const process=service?.process?.state ?? service?.process?.status ?? service?.process;
  const readiness=service?.readiness;
  const row=(key,value,detail)=>h('div',{class:'evidence-row'},h('span',{class:'evidence-label'},tx(key)),h('span',{class:'status '+(value===true||value==='ready'?'ready':value===false?'failed':'')},known(value)),h('span',{class:'muted'},detail));
  return h('div',{},h('div',{class:'instrument'},h('div',{class:'instrument-top'},h('div',{},h('div',{class:'private-label'},tx('readiness')),h('div',{class:'instrument-title'},known(readiness?.overall))),h('div',{class:'actions'},button('start',()=>action(['service','start'],{after:refreshOverview}),'primary',!isLive()),button('stop',()=>action(['service','stop'],{confirm:true,after:refreshOverview}),'',!isLive()),button('restart',()=>action(['service','restart','current'],{confirm:true,after:refreshOverview}),'',!isLive()))),
    h('div',{class:'evidence-list'},row('process',process,'service.status'),row('api',service?.api?.ready ?? service?.API?.ready,'loopback / Clash API'),row('dataplane',readiness?.dataplane?.ready ?? (typeof readiness?.dataplane==='boolean'?readiness.dataplane:null),known(readiness?.dataplane?.mode ?? transparent?.effective?.mode ?? transparent?.configured?.transparent ?? transparent?.configured?.mode)))),
    h('p',{class:'lede'},tx('evidence')),
    h('div',{class:'split'},section('nextStep',h('p',{},tx('setupHelp')),h('a',{class:'tab',href:'#subscriptions'},tx('importSources')),h('div',{class:'actions'},button('preflight',()=>readMachine(['network','preflight'],'network.preflight').catch(()=>{}),'',!isLive()),button('onboardingTitle',onboarding))),
    section('mode',field('mode',select('overview-mode',['tun','ebpf'],transparent?.configured?.transparent||transparent?.configured?.mode||'tun')),button('apply',()=>action(['transparent','set',document.getElementById('overview-mode').value],{confirm:true,after:refreshOverview}),'',!isLive()),...viewStatus('transparent.status'))),
    section('hotspot',h('p',{class:'muted'},tx('hotspotHelp')),h('div',{class:'actions'},button('proxy',()=>action(['hotspot','enable'],{confirm:true,after:refreshOverview}),'',!isLive()),button('direct',()=>action(['hotspot','disable'],{confirm:true,after:refreshOverview}),'',!isLive())),...viewStatus('hotspot.status')),
    rawDetails(service));
}

async function enterPage() {
  if(!isLive()){renderPage();return;}
  const route=state.route;
  try {
    if(route==='overview')await refreshOverview();
    else if(route==='subscriptions')await readSubscriptions();
    else if(route==='paths')await Promise.allSettled([readRouting(),readMachine(['wifi','status'],'wifi.status',{render:false}),readMachine(['network','status'],'network.status',{render:false})]);
    else if(route==='apps')await readApps();
    else if(route==='nodes'||route==='groups')await readNodes();
    else if(route==='chain')await loadPrivateHuman('chain.status',['chain','status']);
    else if(route==='block')await loadPrivateHuman('block.list',['block','list']);
    else if(route==='tailscale')await readMachine(['tailscale','status'],'tailscale.status',{render:false});
    else if(route==='config')await readConfig();
    else if(route==='panel')await loadPrivateHuman('api.stats',['api','stats']);
    else if(route==='health')await refreshOverview();
    else if(route==='tools')await Promise.allSettled([readMachine(['module-update','status'],'module-update.status',{render:false}),readMachine(['network-access','status'],'network-access.status',{render:false}),readMachine(['dns','status'],'dns.status',{render:false})]);
  }catch(error){toast('failed','error',{code:safeCode(error)});}
  if(state.route===route)renderPage();
}
const privateSnapshots=new Map();
async function loadPrivateHuman(name,args){const value=await readHuman(args,{privateRead:true});privateSnapshots.set(name,value);return value;}

bridge.addEventListener('change',updateOperation);
bridge.addEventListener('warning',event=>toast('failed','warning',{code:event.detail.code}));
bridge.addEventListener('exit',event=>{if(event.detail.late){state.workflow=null;updateOperation();refreshOverview().catch(()=>{});}});
window.addEventListener('hashchange',()=>{const id=location.hash.slice(1);if(pages.some(([p])=>p===id)||id==='groups'){state.route=id;renderPage();enterPage();}});
window.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k' || event.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)&&!document.activeElement?.isContentEditable){event.preventDefault();openPalette();}});
window.addEventListener('beforeunload',event=>{if([state.sources,state.ua,state.filters,state.config,state.override,state.repository].some(d=>d.dirty)||state.workflow){event.preventDefault();event.returnValue='';}});
setInterval(updateOperation,1000);

async function readSubscriptions(submitted=null) {
  const request=++state.sources.readSequence;
  try {
    const data=validateSubscription(await readMachine(['sub','inspect'],'sub.inspect',{privateRead:true,render:false}),true,hasFeature('subscription_batch_v1'));
    const rows=await usageRows(data);
    if(request!==state.sources.readSequence)return null;
    state.subscription=data;state.usage=rows;
    state.sources.accept(data.configuration.sing_box_urls.join('\n'),submitted?.sources || null);
    state.ua.accept(data.configuration.user_agent,submitted?.ua || null);
    state.filters.accept(data.configuration.filters.join('\n'),submitted?.filters || null);
    state.errors.delete('sub.inspect');return data;
  }catch(error){
    if(request===state.sources.readSequence){state.subscription=null;state.usage=[];state.sources.loaded=false;state.ua.loaded=false;state.filters.loaded=false;state.errors.set('sub.inspect',safeCode(error));}
    throw error;
  }
}
function counts(items){return h('div',{class:'count-row'},items.map(([key,value])=>h('div',{class:'count'},h('strong',{},known(value)),h('small',{},tx(key)))));}
function dirtyBadge(draft){return h('span',{class:'dirty '+(!draft.dirty?'clean':'')},tx(draft.dirty?'unsaved':'clean'));}
function subscriptionBatch() {
  const sub=state.subscription, batch=sub?.last?.batch;
  if(!hasFeature('subscription_batch_v1'))return notice('unsupportedBatch');
  if(!batch)return h('p',{class:'muted'},tx('noBatch'));
  return h('div',{},h('p',{},h('code',{},batch.generation_id),' · ',h('strong',{},batch.outcome),' · ',h('code',{},batch.error_code)),
    h('div',{class:'list'},batch.sources.map(source=>h('div',{class:'list-row'},h('div',{class:'row-body'},h('div',{class:'primary-text'},tx('candidate',{index:source.index})),h('div',{class:'secondary-text'},source.stage+' / '+source.fetch_result+' / '+source.convert_result)),h('div',{},h('code',{},source.error_code),h('small',{},' · '+known(source.imported_count)))))));
}
function subscriptionsPage() {
  const sub=state.subscription;
  const textarea=h('textarea',{id:'subscription-urls',class:'source-editor',value:state.sources.value,spellcheck:'false',autocapitalize:'off',autocomplete:'off',onInput:event=>{state.sources.edit(event.target.value);state.sourcePreview=null;updateSourceFormState();}});
  const preview=state.sourcePreview;
  const editing=sourceEditorVisible(state.sources,sub?.source.configured_count,state.sourcesOpen);
  const saveButton=button(state.sources.value.trim()?sub?.source?.configured_count?'saveApply':'addEnable':'clearSources',saveSources,'primary',!isLive()||!state.sources.loaded||!state.sources.dirty||Boolean(state.workflow));saveButton.id='save-sources';
  const editor=h('div',{id:'source-editor',hidden:!editing},field('sourceLabel',textarea,'sourceHelp'),h('div',{id:'source-dirty'},dirtyBadge(state.sources)),
    h('div',{class:'actions'},button('sourceSyntax',()=>{state.sourcePreview=sourcePreview(state.sources.value);renderPage();}),button('tidy',()=>{const p=sourcePreview(state.sources.value);if(p.invalid){state.sourcePreview=p;renderPage();return;}state.sources.edit(p.unique.join('\n'));state.sourcePreview=sourcePreview(state.sources.value);renderPage();}),button('paste',async()=>{try{state.sources.edit(await navigator.clipboard.readText());renderPage();}catch{toast('failed','error',{code:'clipboard.unavailable'});}})),
    preview?h('div',{},notice('sourceSyntaxOnly',''),h('p',{},tx('previewCounts',preview)),preview.fragments?notice('fragments'):null,h('div',{class:'list'},preview.rows.map(row=>h('div',{class:'list-row'},h('span',{},row.index+'. '+(row.host?'https://'+row.host:t('unknown'))),h('code',{},row.status))))):null,
    h('div',{class:'actions'},saveButton,button('cancel',()=>{state.sources.reset();state.sourcesOpen=false;state.sourcePreview=null;renderPage();document.getElementById('manage-sources')?.focus();})),
    notice('sourcesPrivacy',''));
  const localInput=input('subscription-file','',{type:'file',accept:'.yaml,.yml,.json,.txt,.list,.conf',onChange:async event=>{
    const file=event.target.files[0];event.target.value='';if(!file)return;
    try {
      if(!file.size||file.size>8*1024*1024)throw new ControlError('subscription.file_size');
      const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      if(!text.trim()||text.includes('\0'))throw new ControlError('subscription.invalid_text');
      state.localFile={text,name:file.name,size:file.size};renderPage();
    }catch(error){state.localFile=null;toast('failed','error',{code:safeCode(error)});}
  }});
  const manage=button('manage',()=>{state.sourcesOpen=true;renderPage();document.getElementById('subscription-urls')?.focus();});manage.id='manage-sources';
  return h('div',{},h('p',{class:'lede'},tx('sourcesPrivacy')),
    state.errors.has('sub.inspect')?notice('sourceReadFailed','error'):null,
    counts([['savedCount',sub?.source?.configured_count],['draftCount',sourcePreview(state.sources.value).unique.length],['attemptCount',sub?.last?.batch?.unique_count],['importedNodes',sub?.last?.imported_count]]),
    h('div',{class:'actions'},!editing?manage:null,button('update',()=>refreshSubscriptions(),'',!sub?.source?.configured_count||!isLive()||Boolean(state.workflow)),button('refresh',async()=>{try{await readSubscriptions();renderPage();}catch{renderPage();}},'',!isLive())),
    state.sourceOutcome?notice(state.sourceOutcome,state.sourceOutcome==='committed'?'':'warning'):null,editor,
    section('localFile',field('importFile',localInput,'fileHelp'),state.localFile?h('div',{},h('p',{},state.localFile.name+' · '+state.localFile.size+' bytes'),button('addEnable',saveLocalSource,'primary',!isLive()||!state.sources.loaded||Boolean(state.workflow))):null),
    section('usage',h('div',{class:'usage-grid'},state.usage.map(row=>h('div',{class:'usage-row'},h('strong',{},row.local?t('localFile'):(row.index+'. '+row.host)),h('small',{},row.state==='cached'?t('cached'):row.state),!row.local?h('div',{},h('p',{},row.used===null?t('unknown'):t('used',{value:formatBytes(row.used)})),row.total>0?h('small',{},t('remaining',{value:row.remaining===null?t('unknown'):formatBytes(row.remaining)})):h('small',{},tx('quotaUnknown')),row.expires?h('small',{},t('expires',{value:new Date(row.expires*1000).toLocaleString(locale)})):h('small',{},tx('expirationUnknown'))):null)))),
    section('batch',subscriptionBatch()),subscriptionSettings(),rawDetails(sub?{source:sub.source,update:sub.update,last:sub.last,schedule:sub.schedule}:null));
}
function updateSourceFormState(){
  const badge=document.getElementById('source-dirty');if(badge)badge.replaceChildren(dirtyBadge(state.sources));
  const btn=document.getElementById('save-sources');if(btn){btn.disabled=!isLive()||!state.sources.loaded||!state.sources.dirty||Boolean(state.workflow);btn.replaceChildren(tx(state.sources.value.trim()?state.subscription?.source.configured_count?'saveApply':'addEnable':'clearSources'));}
}
function formatBytes(value){if(value<1024)return value+' B';const units=['KiB','MiB','GiB','TiB'];let index=-1;do{value/=1024;index++;}while(value>=1024&&index<units.length-1);return value.toFixed(value<10?2:1)+' '+units[index];}
function receiptOf(result){
  if(result.receipt && typeof result.receipt==='object')return result.receipt;
  try {const parsed=JSON.parse(result.stdout);return parsed.receipt||parsed.data?.receipt||parsed.data||parsed;}catch{return null;}
}
async function finishSubscription(result, snapshot) {
  checkExit(result);
  const receipt=receiptOf(result);
  const data=await readSubscriptions();
  const generation=receipt?.generation_id;
  // The transport identifies this invocation. The CLI receipt independently
  // identifies the subscription task; its generation must be the inspected one.
  const operationMatches=!receipt?.operation_id || receipt.operation_id===data?.last.operation_id;
  const modeMatches=data?.source.mode===snapshot.mode;
  const sourcesMatch=snapshot.mode==='local_file'||JSON.stringify(data?.configuration.sing_box_urls)===JSON.stringify(snapshot.urls);
  const committed=data?.last.result==='success'&&(!hasFeature('subscription_batch_v1')||data.last.batch?.outcome==='committed');
  if(!generation||!operationMatches||generation!==data?.last.generation_id||generation===snapshot.baselineGeneration||!modeMatches||!sourcesMatch||!committed){state.sourceOutcome='notBound';renderPage();return;}
  state.frozen={...snapshot,generation_id:generation};
  const savedText=snapshot.mode==='remote_url'?snapshot.urls.join('\n'):'';
  state.sources.accept(savedText,snapshot.draft);
  if(!state.sources.dirty)state.sourcesOpen=false;
  state.sourceOutcome=data.last.batch?.warning_code==='selector_replay_failed'?'selectorWarning':'committed';
  state.localFile=null;renderPage();
}
async function saveUserAgentBeforeSources() {
  if(!state.ua.dirty)return;
  const snapshot=state.ua.snapshot(),value=validateUserAgent(snapshot.value);
  await command(value?['sub','user-agent','set',base64UTF8(value)]:['sub','user-agent','clear']);
  const data=validateSubscription(await bridge.machine(['sub','inspect'],'sub.inspect',{privateRead:true}),true,hasFeature('subscription_batch_v1'));
  if(data.configuration.user_agent!==value)throw new ControlError('user_agent.readback_mismatch');
  state.ua.accept(value,snapshot);toast('uaSeparate');
}
async function saveSources() {
  const frozenDraft=state.sources.snapshot();
  if(!frozenDraft.value.trim()){
    await workflow('subscription.clear',async()=>{
      await command(['sub','clear']);
      const data=await readSubscriptions({sources:frozenDraft});
      if(data?.source.configured_count!==0)throw new ControlError('subscription.clear_unconfirmed');
      state.usage=[];state.sourceOutcome=null;renderPage();
    },{confirm:'clearHelp'});return;
  }
  const preview=sourcePreview(frozenDraft.value);state.sourcePreview=preview;
  if(!preview.canSave){renderPage();return;}
  const snapshot={draft:frozenDraft,urls:[...preview.unique],mode:'remote_url',baselineGeneration:state.subscription?.last.generation_id};
  await workflow('subscription.sources.apply',async()=>{
    if(!state.subscription||!state.sources.loaded)throw new ControlError('subscription.baseline_unknown');
    if(state.subscription.update.owner==='active'||['unknown','pending'].includes(state.subscription.update.owner)||state.subscription.update.transaction_pending)throw new ControlError('subscription.busy');
    await saveUserAgentBeforeSources();
    const result=await privatePayload(bridge,snapshot.urls.join('\n')+'\n','subscription','apply-subscription',{label:'subscription.sources.apply'});
    await finishSubscription(result,snapshot);
  });
}
async function saveLocalSource() {
  if(!state.localFile)return;
  const text=state.localFile.text;
  const snapshot={draft:state.sources.snapshot(),urls:[],mode:'local_file',baselineGeneration:state.subscription?.last.generation_id};
  await workflow('subscription.local.apply',async()=>{
    const result=await privatePayload(bridge,text,'subscription','apply-subscription-source',{label:'subscription.local.apply'});
    await finishSubscription(result,snapshot);
  },{confirm:true});
}
async function refreshSubscriptions() {
  const data=state.subscription;
  if(!data?.source.configured_count)return;
  const snapshot={draft:state.sources.snapshot(),urls:[...data.configuration.sing_box_urls],mode:data.source.mode,baselineGeneration:data.last.generation_id};
  await workflow('subscription.update',async()=>{await finishSubscription(await command(['sub','update','sing-box'],{timeout:120000}),snapshot);},{confirm:true});
}
function subscriptionSettings() {
  const uaPresets=[['','default'],['sing-box','sing-box'],['clash.meta','Mihomo'],['ClashforWindows','Clash for Windows'],['Shadowrocket','Shadowrocket'],['v2rayNG','v2rayNG']];
  const ua=input('subscription-ua',state.ua.value,{autocomplete:'off',onInput:event=>{state.ua.edit(event.target.value);document.getElementById('ua-bytes').textContent=t('byteCount',{count:utf8Length(event.target.value)});}});
  const presets=select('ua-presets',uaPresets,uaPresets.some(([value])=>value===state.ua.value)?state.ua.value:'',event=>{state.ua.edit(event.target.value);renderPage();});
  const filters=h('textarea',{id:'subscription-filters',value:state.filters.value,onInput:event=>state.filters.edit(event.target.value)});
  const schedule=select('subscription-schedule',[['off','off'],['12','12'],['24','24'],['48','48'],['72','72']],state.subscription?.schedule?.interval_hours||'off');
  return section('settings',h('div',{class:'split'},h('div',{},h('h3',{},tx('userAgent')),field('userAgent',ua,'uaHelp'),h('small',{id:'ua-bytes'},tx('byteCount',{count:utf8Length(state.ua.value)})),field('userAgent',presets),button('save',()=>saveSubscriptionSetting('ua'),'primary',!state.ua.loaded||!isLive())),
    h('div',{},h('h3',{},tx('filter')),field('filter',filters,'filterHelp'),h('div',{class:'actions'},...['免费','free','HK','香港','TW','台湾'].map(word=>h('button',{onClick:()=>{state.filters.edit([...normalizeFilters(state.filters.value),word].join('\n'));renderPage();}},word))),button('save',()=>saveSubscriptionSetting('filters'),'primary',!state.filters.loaded||!isLive()))),
    h('hr'),field('schedule',schedule,'scheduleHelp'),h('p',{class:'muted'},known(state.subscription?.schedule)),button('save',()=>action(['sub','schedule','set',schedule.value],{after:async()=>{await readSubscriptions();renderPage();}}),'',!isLive()));
}
async function saveSubscriptionSetting(kind) {
  const draft=kind==='ua'?state.ua:state.filters,snapshot=draft.snapshot();
  await workflow('subscription.'+kind+'.save',async()=>{
    const value=kind==='ua'?validateUserAgent(snapshot.value):normalizeFilters(snapshot.value);
    if(kind==='ua')await command(value?['sub','user-agent','set',base64UTF8(value)]:['sub','user-agent','clear']);
    else await command(value.length?['sub','filter','set',base64UTF8(value.join('\n'))]:['sub','filter','clear']);
    const data=await readSubscriptions({[kind]:snapshot});
    const saved=kind==='ua'?data.configuration.user_agent:data.configuration.filters.join('\n');
    if(saved!==(kind==='ua'?value:value.join('\n')))throw new ControlError('subscription.setting_readback');
    draft.accept(saved,snapshot);toast(kind==='ua'?'uaSeparate':'finished');renderPage();
    if(data.source.configured_count){
      const refreshSnapshot={draft:state.sources.snapshot(),urls:[...data.configuration.sing_box_urls],mode:data.source.mode,baselineGeneration:data.last.generation_id};
      await finishSubscription(await command(['sub','update','sing-box'],{timeout:120000}),refreshSnapshot);
    }
  });
}

async function readRouting(force=false) {
  if(force&&state.override.dirty&&!await confirmRisk('discard'))return;
  const data=await readMachine(['override','inspect'],'override.inspect',{privateRead:true,render:false});
  if(!data||!Number.isSafeInteger(data.revision)||!data.patch||typeof data.patch!=='object'||Array.isArray(data.patch)||!Array.isArray(data.routing_targets))throw new ControlError('override.invalid_inspect');
  state.overrideRevision=data.revision;state.routingTargets=data.routing_targets.filter(v=>v&&typeof v.tag==='string'&&typeof v.type==='string');
  const value=JSON.stringify(data.patch,null,2);
  if(force){state.override.value=value;state.override.baseline=value;state.override.loaded=true;state.override.revision++;}
  else state.override.accept(value);
  try{const patch=JSON.parse(state.override.value);state.routing=structuredClone(patch.$magicnet_routing||{schema:1,rules:[],outbounds:[]});}catch{throw new ControlError('override.draft_invalid');}
  state.previewRevision=-1;
}
function routeTargets(){
  const customNames=new Set(state.routing.outbounds.map(o=>o.tag));
  const base=state.routingTargets.filter(o=>!customNames.has(o.tag));
  // Targets owned by a deleted custom item must not reappear from the active snapshot.
  let savedCustom=[];try{savedCustom=JSON.parse(state.override.baseline).$magicnet_routing?.outbounds?.map(o=>o.tag)||[];}catch{}
  return [...base.filter(o=>!savedCustom.includes(o.tag)),...state.routing.outbounds.map(({tag,type})=>({tag,type}))];
}
function targetLabel(tag){const names=new Map([['proxy','proxy'],['direct','direct'],['block','reject'],['auto','automatic'],['urltest','automatic']]);return names.has(tag)?t(names.get(tag))+' · '+tag:tag;}
function targetSelect(id,current='proxy'){
  const el=h('select',{id});for(const target of routeTargets())el.append(h('option',{value:target.tag},targetLabel(target.tag)+' ('+target.type+')'));
  if(!el.options.length)el.append(h('option',{value:''},t('unknown')));
  el.value=current;return el;
}
function markRouting(){
  let patch;try{patch=JSON.parse(state.override.value);}catch{throw new ControlError('override.invalid_json');}
  if(!patch||typeof patch!=='object'||Array.isArray(patch))throw new ControlError('override.object_required');
  patch.$magicnet_routing=structuredClone(state.routing);state.override.edit(JSON.stringify(patch,null,2));state.routingRevision++;state.previewRevision=-1;
}
async function editRule(index=-1){
  const current=state.routing.rules[index]||{kind:'domain',value:'',outbound:'proxy'};
  const kind=select('route-kind',[['domain','domainKind'],['app','appKind']],current.kind);
  const val=input('route-value',current.value,{autocomplete:'off',list:'installed-apps'}),target=targetSelect('route-target',current.outbound);
  const error=h('div',{'aria-live':'polite'});
  const content=h('div',{},field('ruleKind',kind),field('value',val),h('datalist',{id:'installed-apps'},state.apps.map(a=>h('option',{value:a.packageName},a.appLabel))),field('target',target),error);
  const previous=document.activeElement;const modal=h('dialog',{'aria-labelledby':'rule-title'},h('h2',{id:'rule-title'},tx('addRule')),content);
  const finish=()=>{modal.close();modal.remove();previous?.isConnected&&previous.focus();};
  modal.append(h('div',{class:'dialog-actions'},button('cancel',finish),button('save',()=>{
    try{
      let value=val.value.trim();if(kind.value==='domain'){
        if(/[\s/?#:@]/.test(value))throw new ControlError('override.routing_invalid');
        value=new URL('https://'+value).hostname.toLowerCase();
        if(!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)||value.includes('..'))throw new ControlError('override.routing_invalid');
      }else if(!/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/.test(value))throw new ControlError('override.routing_invalid');
      if(!routeTargets().some(o=>o.tag===target.value))throw new ControlError('override.routing_target_missing');
      if(state.routing.rules.some((r,i)=>i!==index&&r.kind===kind.value&&r.value===value))throw new ControlError('override.routing_duplicate');
      if(index<0&&state.routing.rules.length>=256)throw new ControlError('override.routing_limit');
      const row={kind:kind.value,value,outbound:target.value};if(index<0)state.routing.rules.push(row);else state.routing.rules[index]=row;
      markRouting();finish();renderPage();
    }catch(e){error.replaceChildren(notice('failed','error',{code:safeCode(e)}));}
  },'primary')));
  modal.addEventListener('cancel',e=>{e.preventDefault();finish();});document.getElementById('dialogs').append(modal);modal.showModal();val.focus();
}
async function editOutbound(index=-1){
  const original=state.routing.outbounds[index]||{type:'selector',tag:'',outbounds:[],default:''};
  const type=select('outbound-type',['selector','urltest','socks','http','shadowsocks','trojan','vless','vmess','hysteria2','tuic','anytls'],original.type);
  const tag=input('outbound-tag',original.tag),members=h('textarea',{id:'outbound-members',value:(original.outbounds||[]).join('\n')});
  const defaults=input('outbound-default',original.default||'');
  const server=input('outbound-server',original.server||''),port=input('outbound-port',original.server_port||443,{type:'number',min:1,max:65535});
  const username=input('outbound-user',original.username||'',{autocomplete:'off'}),password=input('outbound-password',original.password||'',{type:'password',autocomplete:'new-password'}),uuid=input('outbound-uuid',original.uuid||'',{autocomplete:'off'}),encryption=input('outbound-encryption',original.encryption||'',{type:'password',autocomplete:'new-password'});
  const omitted=new Set(['type','tag','outbounds','default','server','server_port','username','password','uuid','encryption']);
  const extra={};for(const [key,value]of Object.entries(original))if(!omitted.has(key))Object.defineProperty(extra,key,{value,enumerable:true,writable:true,configurable:true});
  const advanced=h('textarea',{id:'outbound-advanced',value:JSON.stringify(extra,null,2),spellcheck:false});
  const groupFields=h('div',{},field('members',members),field('defaultTarget',defaults));
  const serverFields=h('div',{},h('div',{class:'form-grid'},field('server',server),field('port',port)),field('username',username),field('password',password),field('uuid',uuid),field('encryption',encryption,'encryptionHelp'));
  const toggle=()=>{groupFields.hidden=!['selector','urltest'].includes(type.value);serverFields.hidden=!groupFields.hidden;encryption.closest('.field').hidden=type.value!=='vless';};type.addEventListener('change',toggle);toggle();
  const error=h('div',{'aria-live':'polite'}),previous=document.activeElement;
  const modal=h('dialog',{'aria-labelledby':'outbound-title'},h('h2',{id:'outbound-title'},tx('addOutbound')),field('tag',tag),field('type',type),groupFields,serverFields,field('fullFields',advanced),error);
  const finish=()=>{modal.close();modal.remove();previous?.isConnected&&previous.focus();};
  modal.append(h('div',{class:'dialog-actions'},button('cancel',finish),button('save',()=>{
    try{
      const name=tag.value.trim();if(!name||utf8Length(name)>256||/[\x00-\x1f\x7f]/.test(name))throw new ControlError('override.routing_invalid');
      if(state.routing.outbounds.some((o,i)=>i!==index&&o.tag===name))throw new ControlError('override.routing_tag_collision');
      if(index<0&&state.routing.outbounds.length>=64)throw new ControlError('override.routing_limit');
      const extra=JSON.parse(advanced.value||'{}');if(!extra||typeof extra!=='object'||Array.isArray(extra)||Object.keys(extra).some(k=>omitted.has(k)))throw new ControlError('override.routing_invalid');
      const row={...extra,type:type.value,tag:name};
      if(['selector','urltest'].includes(type.value)){
        row.outbounds=members.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
        if(!row.outbounds.length||row.outbounds.length>128||new Set(row.outbounds).size!==row.outbounds.length)throw new ControlError('override.routing_limit');
        if(defaults.value.trim())row.default=defaults.value.trim();
      }else{
        row.server=server.value.trim();row.server_port=Number(port.value);if(!row.server||!Number.isInteger(row.server_port)||row.server_port<1||row.server_port>65535)throw new ControlError('override.routing_invalid');
        if(username.value)row.username=username.value;if(password.value)row.password=password.value;if(uuid.value)row.uuid=uuid.value;
        if(type.value==='vless'&&encryption.value)row.encryption=encryption.value;
      }
      if(index<0)state.routing.outbounds.push(row);else state.routing.outbounds[index]=row;
      markRouting();finish();renderPage();
    }catch(e){error.replaceChildren(notice('failed','error',{code:safeCode(e)}));}
  },'primary')));
  modal.addEventListener('cancel',e=>{e.preventDefault();finish();});document.getElementById('dialogs').append(modal);modal.showModal();tag.focus();
}
async function overrideOperation(action,fromRouting=false){
  const snapshot=state.override.snapshot(),routingRevision=state.routingRevision;
  if(action==='set'&&state.previewRevision!==snapshot.revision){toast('previewRequired');return;}
  await workflow('override.'+action,async()=>{
    let patch;try{patch=JSON.parse(snapshot.value);}catch{throw new ControlError('override.invalid_json');}
    const payload=action==='apply'?{expected_revision:state.overrideRevision}:{patch,expected_revision:state.overrideRevision};
    const result=await privatePayload(bridge,JSON.stringify(payload),'tmp',path=>['--json','override',action+'-file',path],{label:'override.'+action});
    const data=envelope(result,'override.'+action);
    if(action==='preview'){
      if(data.valid!==true)throw new ControlError('override.preview_failed');
      if(state.override.revision===snapshot.revision)state.previewRevision=snapshot.revision;
      state.snapshots.set('override.preview',data);renderPage();
    }else if(action==='set'){
      state.overrideRevision=data.revision;state.override.accept(snapshot.value,snapshot);toast('finished');renderPage();
    }else {toast('finished');await readMachine(['override','status'],'override.status',{render:false});renderPage();}
  },{confirm:action==='apply'});
}
function routingEditor(){
  return section('routeWorkspace',h('p',{class:'lede'},tx('routeHelp')),h('p',{class:'private-label'},tx('private'),' · ',tx('revision'),' ',known(state.overrideRevision)),
    h('div',{class:'section-header'},h('h3',{},tx('rules')),button('addRule',()=>editRule(),'',!state.override.loaded)),
    h('div',{class:'list'},state.routing.rules.map((r,index)=>h('div',{class:'list-row'},h('div',{class:'row-body'},h('div',{class:'primary-text'},r.value),h('div',{class:'secondary-text'},r.kind+' → '+targetLabel(r.outbound))),h('div',{class:'actions'},button('editor',()=>editRule(index)),button('remove',()=>{state.routing.rules.splice(index,1);markRouting();renderPage();},'danger'))))),
    h('div',{class:'section-header'},h('h3',{},tx('outbounds')),button('addOutbound',()=>editOutbound(),'',!state.override.loaded)),
    h('div',{class:'list'},state.routing.outbounds.map((outbound,index)=>h('div',{class:'list-row'},h('div',{class:'row-body'},h('div',{class:'primary-text'},outbound.tag),h('div',{class:'secondary-text'},outbound.type)),h('div',{class:'actions'},button('editor',()=>editOutbound(index)),button('remove',()=>{state.routing.outbounds.splice(index,1);markRouting();renderPage();},'danger'))))),
    dirtyBadge(state.override),h('div',{class:'actions'},button('previewChanges',()=>overrideOperation('preview',true),'',!state.override.loaded),button('saveDraft',()=>overrideOperation('set',true),'primary',!state.override.loaded||state.previewRevision!==state.override.revision),button('applySaved',()=>overrideOperation('apply',true),'',!state.override.loaded),button('resetDraft',()=>{state.routing={schema:1,rules:[],outbounds:[]};markRouting();renderPage();}),button('reload',async()=>{await readRouting(true);renderPage();})),
    state.previewRevision!==state.override.revision?h('small',{},tx('previewRequired')):rawDetails(state.snapshots.get('override.preview')));
}
function pathsPage(){
  const service=state.snapshots.get('service.status'),data=state.snapshots.get('network.status');
  return h('div',{},h('div',{class:'step-path'},h('div',{class:'step'},h('strong',{},tx('apps')),h('small',{},'proxy / direct / bypass')),h('div',{class:'step'},h('strong',{},tx('dataplane')),h('small',{},known(service?.readiness?.dataplane))),h('div',{class:'step'},h('strong',{},tx('target')),h('small',{},t('unknown')))),
    routingEditor(),wifiEditor(),section('network',h('p',{class:'muted'},tx('intent'),' / ',tx('effective')),networkForm(data),...viewStatus('network.status')));
}
function networkForm(data){
  const config=data?.configured||{};
  const strategy=select('network-strategy',['ipv4_only','prefer_ipv4','prefer_ipv6'],config.strategy||config.ipv6||'prefer_ipv4');
  const mtu=input('network-mtu',config.mtu||1400,{type:'number',min:1280,max:1500}),udp=select('network-udp',['1m','3m','5m','10m','15m','30m'],config.udp_timeout||'5m');
  return h('div',{},h('div',{class:'form-grid'},field('ipv6',strategy),field('mtu',mtu),field('udp',udp)),h('div',{class:'actions'},button('save',()=>action(['network','set',strategy.value,mtu.value,udp.value],{after:()=>readMachine(['network','status'],'network.status')}),'primary',!isLive()),button('apply',()=>action(['network','apply'],{confirm:true,after:()=>readMachine(['network','status'],'network.status')}),'',!isLive()),button('preflight',()=>readMachine(['network','preflight'],'network.preflight').catch(()=>{}),'',!isLive())),...viewStatus('network.preflight'));
}
function wifiEditor(){
  const wifi=privateSnapshots.get('wifi.inspect');
  const ssid=input('wifi-ssid','',{autocomplete:'off'}),bssid=input('wifi-bssid','',{autocomplete:'off'}),interval=input('wifi-interval',wifi?.configured?.interval||wifi?.interval||15,{type:'number',min:3,max:300});
  const mode=select('wifi-mode',['blacklist','whitelist'],wifi?.configured?.mode||'blacklist');
  const refreshWifi=async()=>{const value=await readMachine(['wifi','inspect'],'wifi.inspect',{privateRead:true,render:false});privateSnapshots.set('wifi.inspect',value);renderPage();};
  return section('wifi',h('p',{class:'muted'},tx('wifiHelp')),h('div',{class:'actions'},button('manage',refreshWifi,'',!isLive()),button('enable',()=>action(['wifi','enable'],{after:refreshWifi}),'',!isLive()),button('disable',()=>action(['wifi','disable'],{after:refreshWifi}),'',!isLive())),
    wifi?h('div',{},h('div',{class:'form-grid'},field('listMode',mode),field('interval',interval)),h('div',{class:'actions'},button('save',()=>workflow('wifi.settings',async()=>{await command(['wifi','mode',mode.value]);await command(['wifi','interval',interval.value]);await refreshWifi();}),'',!isLive())),field('ssid',ssid),h('div',{class:'actions'},button('add',()=>action(['wifi','add-ssid',ssid.value],{after:refreshWifi})),button('remove',()=>action(['wifi','remove-ssid',ssid.value],{after:refreshWifi}))),field('bssid',bssid),h('div',{class:'actions'},button('add',()=>action(['wifi','add-bssid',bssid.value],{after:refreshWifi})),button('remove',()=>action(['wifi','remove-bssid',bssid.value],{after:refreshWifi}))),rawDetails(wifi)):null,
    ...viewStatus('wifi.status'));
}

async function readApps(){
  try{
    const data=await readMachine(['app','inspect'],'app.inspect',{privateRead:true,render:false});
    if(data.schema!==1||data.scope!=='owner_user'||!Array.isArray(data.packages)||data.packages.length>4096||data.packages.some(p=>typeof p.packageName!=='string'||typeof p.appLabel!=='string'))throw new ControlError('app.catalog_invalid');
    state.apps=data.packages;
  }catch(error){
    if(!['machine.unsupported','app.catalog_unsupported','app.catalog_unavailable'].includes(safeCode(error))){state.apps=[];throw error;}
    const value=await readHuman(['app','packages'],{privateRead:true});
    const names=Array.isArray(value)?value:Array.isArray(value?.packages)?value.packages:typeof value==='string'?value.trim().split('\n'):[];
    state.apps=names.map(p=>typeof p==='string'?{packageName:p,appLabel:p}:{packageName:p.packageName,appLabel:p.packageName}).filter(p=>typeof p.packageName==='string');
  }
  await loadPrivateHuman('app.list',['app','list']);
}
function appsPage(){
  const query=input('apps-query',state.appQuery,{'data-i18n-placeholder':'searchApps',placeholder:t('searchApps'),onInput:e=>{state.appQuery=e.target.value;renderAppList();}});
  const mode=select('app-list-mode',['blacklist','whitelist'],'blacklist'),policy=select('app-policy',[['proxy','proxy'],['direct','direct'],['bypass','bypass']],'proxy');
  const list=h('div',{id:'app-list',class:'list'});
  const root=h('div',{},h('p',{class:'lede'},tx('appHelp')),field('searchApps',query),h('div',{class:'form-grid'},field('listMode',mode),field('target',policy)),
    h('div',{class:'actions'},button('save',()=>action(['app','mode',mode.value]),'',!isLive()),button('selectAll',()=>{filteredApps().forEach(app=>state.selectedApps.add(app.packageName));renderAppList();}),button('setSelected',()=>action(['app','add-many',policy.value,...state.selectedApps],{after:readApps}),'primary',!isLive()),button('apply',()=>action(['app','apply'],{confirm:true,after:readApps}),'',!isLive())),list,rawDetails(privateSnapshots.get('app.list')));
  populateApps(list);return root;
}
function filteredApps(){const q=state.appQuery.toLowerCase();return state.apps.filter(a=>(a.appLabel+' '+a.packageName).toLowerCase().includes(q));}
function populateApps(list){
  list.replaceChildren(...filteredApps().slice(0,400).map(app=>{
    const box=input('app-'+app.packageName,'',{type:'checkbox',checked:state.selectedApps.has(app.packageName),onChange:event=>{if(event.target.checked)state.selectedApps.add(app.packageName);else state.selectedApps.delete(app.packageName);}});
    return h('div',{class:'list-row'},h('div',{class:'check-row row-body'},box,h('label',{for:box.id},h('div',{class:'primary-text'},app.appLabel),h('div',{class:'secondary-text'},app.packageName))),button('remove',()=>action(['app','remove',app.packageName],{after:async()=>{await readApps();renderPage();}}),'',!isLive()));
  }));
  if(!list.children.length)list.append(h('p',{class:'empty'},tx(isLive()?'noMatches':'noData')));
}
function renderAppList(){const list=document.getElementById('app-list');if(list)populateApps(list);}
async function readNodes(){
  const data=await readHuman(['api','proxies'],{privateRead:true});
  const proxies=data?.proxies||data?.data?.proxies||data;
  if(!proxies||typeof proxies!=='object'||Array.isArray(proxies))throw new ControlError('api.proxies_invalid');
  state.proxies=new Map(Object.entries(proxies));state.groups=new Map([...state.proxies].filter(([,p])=>Array.isArray(p?.all)||['Selector','URLTest','selector','urltest'].includes(p?.type)));
}
function nodesPage(){
  const query=input('node-query',state.nodeQuery,{'data-i18n-placeholder':'searchPages',placeholder:t('searchPages'),onInput:e=>{state.nodeQuery=e.target.value;renderPage();}});
  const groups=state.route==='groups',entries=[...(groups?state.groups:state.proxies)].filter(([name,node])=>(groups||!state.groups.has(name))&&(name+' '+targetLabel(name)).toLowerCase().includes(state.nodeQuery.toLowerCase()));
  return h('div',{},h('div',{class:'tabs'},h('a',{class:'tab',href:'#nodes','aria-current':!groups?'page':null},tx('nodes')),h('a',{class:'tab',href:'#groups','aria-current':groups?'page':null},tx('groups'))),h('p',{class:'lede'},tx('delayHelp')),field('searchPages',query),
    h('div',{class:'actions'},button('testAll',()=>testNodes(entries.map(([tag])=>tag)),'',!isLive()||!entries.length)),
    h('div',{class:'list'},entries.length?entries.map(([name,node])=>{
      const body=h('div',{class:'row-body'},h('div',{class:'primary-text'},targetLabel(name)),h('div',{class:'secondary-text'},name+' · '+(node.type||'unknown')),node.now?h('small',{},tx('current'),': '+targetLabel(node.now)):null);
      if(groups){
        const selection=h('select',{'aria-label':name+' '+t('current')});(node.all||[]).forEach(raw=>selection.append(h('option',{value:raw},targetLabel(raw))));selection.value=node.now||'';
        const test=state.delays.get(name);
        return h('div',{class:'list-row'},body,selection,h('div',{class:'actions'},button('choose',()=>action(['api','select',name,selection.value],{confirm:true,after:async()=>{await readNodes();renderPage();}}),'',!isLive()),button('test',()=>testNodes([name]),'',!isLive())),test?h('pre',{},JSON.stringify(test,null,2)):null);
      }
      return h('div',{class:'list-row'},body,h('div',{class:'actions'},button('test',()=>testNodes([name]),'',!isLive()),button('choose',()=>action(['node','use',name],{confirm:true,after:async()=>{await readNodes();renderPage();}}),'',!isLive())),state.delays.has(name)?h('code',{},known(state.delays.get(name))):null);
    }):h('p',{class:'empty'},tx('emptyNodes'))));
}
async function testNodes(tags){
  await workflow('node.delay',async()=>{
    for(const tag of tags.slice(0,128)){
      const result=await command(['node','test',tag],{timeout:30000});let data;try{data=JSON.parse(result.stdout);}catch{data={state:'unknown'};}state.delays.set(tag,data);
    }renderPage();
  });
}
function blockPage(){
  const domain=input('block-domain','',{autocomplete:'off'}),allow=input('block-allow','',{autocomplete:'off'});
  const refresh=async()=>{await loadPrivateHuman('block.list',['block','list']);renderPage();};
  return h('div',{},h('p',{class:'lede'},tx('blockHelp')),h('div',{class:'actions'},button('enable',()=>action(['block','enable'],{after:refresh}),'',!isLive()),button('disable',()=>action(['block','disable'],{after:refresh}),'',!isLive()),button('apply',()=>action(['block','apply'],{confirm:true,after:refresh}),'primary',!isLive())),
    section('blockDomain',field('blockDomain',domain),h('div',{class:'actions'},button('add',()=>action(['block','add-domain',domain.value],{after:refresh}),'',!isLive()),button('remove',()=>action(['block','remove-domain',domain.value],{after:refresh}),'',!isLive()))),
    section('allowRule',field('allowRule',allow),h('div',{class:'actions'},button('add',()=>action(['block','allow-rule',allow.value],{after:refresh}),'',!isLive()),button('remove',()=>action(['block','unallow-rule',allow.value],{after:refresh}),'',!isLive()))),
    section('community',h('div',{class:'actions'},button('enable',()=>action(['block','community','on'],{after:refresh}),'',!isLive()),button('disable',()=>action(['block','community','off'],{after:refresh}),'',!isLive()),button('update',()=>action(['block','update'],{after:refresh}),'',!isLive()))),rawDetails(privateSnapshots.get('block.list')));
}
function chainPage(){
  const data=privateSnapshots.get('chain.status');
  const upstream=input('chain-upstream',data?.upstream||''),exit=input('chain-exit',data?.exit||''),mode=select('chain-mode',['manual','auto'],data?.mode||'manual');
  return h('div',{},h('div',{class:'form-grid'},field('upstream',upstream),field('exit',exit),field('chainMode',mode)),h('div',{class:'actions'},button('save',()=>workflow('chain.configure',async()=>{await command(['chain','set-upstream',upstream.value]);await command(['chain','set-exit',exit.value]);await command(['chain','mode',mode.value]);await loadPrivateHuman('chain.status',['chain','status']);renderPage();}),'primary',!isLive()),button('enable',()=>action(['chain','enable'],{confirm:true,after:enterPage}),'',!isLive()),button('disable',()=>action(['chain','disable'],{confirm:true,after:enterPage}),'',!isLive()),button('clear',()=>workflow('chain.clear',async()=>{await command(['chain','clear-upstream']);await command(['chain','clear-exit']);await enterPage();}),'',!isLive())),rawDetails(data));
}
function tailscalePage(){
  const data=state.snapshots.get('tailscale.status');
  const revision=data?.revision??data?.configured?.revision;
  return h('div',{},h('p',{class:'lede'},tx('tailscaleHelp')),counts([['revision',revision],['intent',data?.enabled??data?.configured?.enabled],['effective',data?.online??data?.effective?.online]]),h('div',{class:'actions'},button('resume',()=>action(['tailscale','enable',String(revision)],{after:enterPage}),'primary',revision===undefined||!isLive()),button('pause',()=>action(['tailscale','disable',String(revision)],{after:enterPage}),'',revision===undefined||!isLive()),button('logout',()=>action(['tailscale','logout',String(revision)],{confirm:true,after:enterPage}),'danger',revision===undefined||!isLive())),rawDetails(data));
}

async function readConfig(force=false){
  if(force&&state.config.dirty&&!await confirmRisk('discard'))return;
  const sequence=++state.config.readSequence;
  try{
    const data=await readHuman(['config-editor','get','sing-box'],{privateRead:true});
    const value=typeof data==='string'?data:JSON.stringify(data,null,2);const parsed=JSON.parse(value);
    if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new ControlError('config.invalid_json');
    if(sequence!==state.config.readSequence)return;
    if(force){state.config.value=value;state.config.baseline=value;state.config.loaded=true;state.config.revision++;}else state.config.accept(value);
    state.errors.delete('config');
  }catch(error){if(sequence===state.config.readSequence){state.config.loaded=false;state.errors.set('config',safeCode(error));}throw error;}
  if(!state.override.loaded)await readRouting();
}
function downloadText(filename,text){const a=h('a',{download:filename,href:URL.createObjectURL(new Blob([text],{type:'application/json'}))});a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
function configPage(){
  const draft=state.configTab==='override'?state.override:state.config;
  const editor=h('textarea',{id:'config-text',class:'editor',value:draft.value,spellcheck:false,autocapitalize:'off',autocomplete:'off',onInput:event=>{draft.edit(event.target.value);if(state.configTab==='override')state.previewRevision=-1;document.getElementById('config-dirty').replaceChildren(dirtyBadge(draft));}});
  const importer=input('config-import','',{type:'file',accept:'.json',onChange:async event=>{
    const file=event.target.files[0];event.target.value='';if(!file)return;
    if(draft.dirty&&!await confirmRisk('discard'))return;
    try{if(file.size>4*1024*1024)throw new ControlError('config.size_limit');const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());JSON.parse(text);draft.edit(text);renderPage();}catch(e){toast('failed','error',{code:safeCode(e)});}
  }});
  const override=state.configTab==='override';
  return h('div',{},h('div',{class:'tabs'},button('editor',()=>{state.configTab='editor';renderPage();},!override?'primary':''),button('override',()=>{state.configTab='override';renderPage();},override?'primary':'')),h('p',{class:'lede'},tx(override?'patchHelp':'configHelp')),state.errors.has('config')?notice('failed','error',{code:state.errors.get('config')}):null,
    field(override?'override':'editor',editor),h('div',{id:'config-dirty'},dirtyBadge(draft)),
    h('div',{class:'actions'},button('format',()=>{try{const pos=editor.selectionStart;draft.edit(JSON.stringify(JSON.parse(draft.value),null,2));editor.value=draft.value;editor.focus();editor.setSelectionRange(Math.min(pos,editor.value.length),Math.min(pos,editor.value.length));document.getElementById('config-dirty').replaceChildren(dirtyBadge(draft));}catch{toast('failed','error',{code:'config.invalid_json'});}}),
      button('reload',async()=>{try{if(override)await readRouting(true);else await readConfig(true);renderPage();}catch(e){toast('failed','error',{code:safeCode(e)});}},'',!isLive()),button('exportDraft',()=>downloadText(override?'magicnet-override.json':'magicnet-config.json',draft.value))),
    field('importJSON',importer),
    override?h('div',{class:'actions'},button('previewChanges',()=>overrideOperation('preview'),'',!draft.loaded),button('saveDraft',()=>overrideOperation('set'),'primary',!draft.loaded||state.previewRevision!==draft.revision),button('applySaved',()=>overrideOperation('apply'),'',!draft.loaded),button('resetDraft',()=>{draft.edit('{}');state.previewRevision=-1;renderPage();})):h('div',{class:'actions'},button('validate',()=>saveConfig(false),'',!draft.loaded||!isLive()),button('save',()=>saveConfig(true),'primary',!draft.loaded||!isLive()),button('apply',()=>action(['config','apply'],{confirm:true,after:refreshOverview}),'',!draft.loaded||!isLive())),
    override?rawDetails(state.snapshots.get('override.preview')):templateEditor());
}
async function saveConfig(save){
  const snapshot=state.config.snapshot();
  await workflow(save?'config.save':'config.validate',async()=>{
    try{JSON.parse(snapshot.value);}catch{throw new ControlError('config.invalid_json');}
    const result=await privatePayload(bridge,snapshot.value,'tmp',path=>['config-editor',save?'save-file':'validate','sing-box',path],{label:save?'config.save':'config.validate'});checkExit(result);
    if(save)state.config.accept(snapshot.value,snapshot);toast('finished');renderPage();
  });
}
function templateEditor(){
  const draft=h('textarea',{id:'template-repository',value:state.repository.value,onInput:event=>state.repository.edit(event.target.value)});
  return section('template',field('repository',draft),h('div',{class:'actions'},button('refresh',async()=>{if(state.repository.dirty&&!await confirmRisk('discard'))return;try{const value=await readHuman(['config-editor','repo','get-json'],{privateRead:true});state.repository.accept(JSON.stringify(value,null,2));renderPage();}catch(e){toast('failed','error',{code:safeCode(e)});}},'',!isLive()),
    button('save',()=>workflow('config.repository.save',async()=>{const snapshot=state.repository.snapshot();JSON.parse(snapshot.value);checkExit(await privatePayload(bridge,snapshot.value,'tmp',path=>['config-editor','repo','set-file',path]));state.repository.accept(snapshot.value,snapshot);toast('finished');}),'',!isLive()),
    button('templateSync',async()=>{if(state.config.dirty&&!await confirmRisk('discard'))return;await action(['config-editor','sync-template','sing-box'],{confirm:true,after:()=>readConfig(true)});},'',!isLive())));
}

function panelPage(){
  const query=input('connection-query','',{autocomplete:'off'});
  const conns=privateSnapshots.get('api.conns'),stats=privateSnapshots.get('api.stats');
  return h('div',{},h('p',{class:'lede'},tx('panelHelp')),h('div',{class:'actions'},button('openPanel',async()=>{
    try{
      const value=await readHuman(['api','ui','sing-box'],{privateRead:true});
      const raw=typeof value==='string'?value.trim():value.url||value.endpoint;
      const url=new URL(raw);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.port!=='9090'||url.username||url.password)throw new ControlError('api.panel_endpoint_invalid');
      state.panelVisible=url.href;renderPage();
    }catch(error){toast('failed','error',{code:safeCode(error)});}
  },'primary',!isLive()),button('connections',async()=>{try{await loadPrivateHuman('api.conns',['api','conns']);renderPage();}catch(e){toast('failed','error',{code:safeCode(e)});}},'',!isLive()),button('statistics',async()=>{try{await loadPrivateHuman('api.stats',['api','stats']);renderPage();}catch(e){toast('failed','error',{code:safeCode(e)});}},'',!isLive())),
    state.panelVisible?h('iframe',{class:'panel-frame',src:state.panelVisible,title:t('panel'),referrerpolicy:'no-referrer'}):null,
    section('connections',field('query',query),h('div',{class:'actions'},button('closeMatching',()=>action(['api','close-matching',query.value],{confirm:true,after:enterPage}),'',!isLive()),button('closeAll',()=>action(['api','close-all'],{confirm:true,after:enterPage}),'danger',!isLive())),
      h('div',{class:'list'},(conns?.connections||[]).map(conn=>h('div',{class:'list-row'},h('div',{class:'row-body'},h('div',{class:'primary-text'},String(conn.metadata?.host||conn.metadata?.destinationIP||conn.id)),h('small',{},String(conn.metadata?.network||''))),button('close',()=>action(['api','close',String(conn.id)],{confirm:true,after:async()=>{await loadPrivateHuman('api.conns',['api','conns']);renderPage();}}))))),rawDetails(conns)),section('statistics',rawDetails(stats)));
}
function healthPage(){
  const source=select('log-source',['sing-box','webui','mcp','fswatch','supervisors'],'sing-box'),lines=input('log-lines',100,{type:'number',min:1,max:1000});
  return h('div',{},h('p',{class:'lede'},tx('healthHelp')),h('div',{class:'actions'},button('health',()=>runDiagnostic(['health']),'primary',!isLive()),button('topology',()=>runDiagnostic(['topology']),'',!isLive()),button('preflight',()=>readMachine(['network','preflight'],'network.preflight').catch(()=>{}),'',!isLive()),button('test',()=>runDiagnostic(['pingtest']),'',!isLive())),
    ...viewStatus('service.status'),...viewStatus('transparent.status'),...viewStatus('network.preflight'),
    privateSnapshots.has('diagnostic')?h('pre',{},stringify(privateSnapshots.get('diagnostic'))):null,
    section('logs',h('div',{class:'form-grid'},field('logSource',source),field('lines',lines)),button('refresh',()=>runDiagnostic(['service','logs',source.value,lines.value]),'',!isLive())),section('support',button('support',()=>runDiagnostic(['support','bundle'],true),'',!isLive())));
}
function stringify(value){return typeof value==='string'?value:JSON.stringify(value,null,2);}
async function runDiagnostic(args,write=false){
  if(write){await workflow(args.slice(0,2).join('.'),async()=>{privateSnapshots.set('diagnostic',(await command(args)).stdout);renderPage();});return;}
  try{const value=await readHuman(args,{privateRead:true});privateSnapshots.set('diagnostic',value);record(args.slice(0,2).join('.'),'none',0);renderPage();}catch(error){record(args.slice(0,2).join('.'),safeCode(error));toast('failed','error',{code:safeCode(error)});}
}
function terminalPage(){
  const args=input('terminal-args',state.terminalArgs,{spellcheck:false,autocomplete:'off',onInput:event=>state.terminalArgs=event.target.value});
  return h('div',{},h('p',{class:'lede'},tx('terminalHelp')),field('arguments',args),h('div',{class:'actions'},button('execute',async()=>{
    let parsed;try{parsed=parseArgv(state.terminalArgs);}catch(error){toast('failed','error',{code:safeCode(error)});return;}
    if(!parsed.length)return;
    if(parsed[0].startsWith('__')||parsed[0]==='serve'){toast('failed','error',{code:'terminal.command_denied'});return;}
    await workflow('terminal.command',async()=>{const result=await bridge.execute(parsed,{write:true,label:'terminal.command',privateRead:true,timeout:120000});state.terminalOutput=result.stdout+'\n'+result.stderr;record('terminal.command',result.exit_code===0?'none':'command.failed',result.exit_code);renderPage();},{confirm:true});
  },'primary',!isLive()),button('clear',()=>{state.terminalOutput='';renderPage();})),section('commandOutput',h('pre',{},state.terminalOutput||t('noOutput'))));
}
function outputPage(){
  return h('div',{},h('p',{class:'lede'},tx('recentHelp')),h('div',{class:'actions'},button('copySummary',()=>navigator.clipboard.writeText(JSON.stringify(state.output,null,2)).catch(()=>toast('failed','error',{code:'clipboard.unavailable'}))),button('clearOutput',()=>{state.output=[];renderPage();})),
    h('div',{class:'list'},state.output.length?state.output.map(row=>h('div',{class:'list-row'},h('div',{class:'row-body'},h('div',{class:'primary-text'},row.label),h('div',{class:'secondary-text'},row.time+' · '+row.language)),h('code',{},row.code+' / exit '+known(row.exit_code)))):h('p',{class:'empty'},tx('noOutput'))));
}
function toolsPage(){return h('div',{},h('div',{class:'tool-grid'},moduleUpdateTool(),networkAccessTool(),dnsTool(),warpTool(),mcpTool(),backupTool(),captureTool(),networkTool()),state.privateOutput?section('commandOutput',h('pre',{},state.privateOutput),button('clear',()=>{state.privateOutput='';renderPage();})):null);}
function moduleUpdateTool(){
  const current=state.snapshots.get('module-update.status');
  if(!state.updateID)state.updateID='ui_'+crypto.getRandomValues(new Uint32Array(3)).join('_');
  const request=input('update-request',state.updateID,{onInput:e=>state.updateID=e.target.value}),installed=input('update-installed',current?.effective_version||'',{onInput:e=>state.updateInstalled=e.target.value}),latest=input('update-latest',current?.latest_version||'',{onInput:e=>state.updateLatest=e.target.value});
  const busy=current?.running===true||['checking','downloading','verifying','installing','reboot_required'].includes(current?.phase)||current?.recovery_required===true;
  const update=async action=>{
    const args=['--json','module-update',action,'--request-id',request.value];if(action==='install')args.push('--expected-installed',installed.value,'--expected-latest',latest.value);
    await workflow('module-update.'+action,async()=>{
      const result=await bridge.execute(args,{write:true,label:'module-update.'+action});const data=envelope(result,'module-update.'+action);toast(data.accepted?'submitted':'finished');
      await readMachine(['module-update','status'],'module-update.status');scheduleUpdatePoll();
    },{confirm:action==='install'});
  };
  return section('updateModule',h('p',{class:'muted'},tx('updateHelp')),rawDetails(current),field('requestID',request),h('div',{class:'form-grid'},field('expectedInstalled',installed),field('expectedLatest',latest)),h('div',{class:'actions'},button('checkUpdate',()=>update('check'),'',!isLive()||busy),button('installUpdate',()=>update('install'),'primary',!isLive()||busy||current?.phase!=='available')));
}
let updatePoll=null;
function scheduleUpdatePoll(){
  if(updatePoll)return;
  updatePoll=setTimeout(async()=>{updatePoll=null;try{const data=await readMachine(['module-update','status'],'module-update.status',{render:false});if(state.route==='tools')renderPage();if(data?.running===true)scheduleUpdatePoll();}catch{if(state.route==='tools')renderPage();}},15000);
}
function networkAccessTool(){
  const check=async()=>{
    try{
      const data=await readMachine(['network-access','inspect'],'network-access.inspect',{privateRead:true,render:false});
      if(typeof data?.candidate!=='string'||!Array.isArray(data.records))throw new ControlError('network-access.invalid_candidate');
      const valid=await bridge.machine(['network-access','check',data.candidate],'network-access.check',{privateRead:true});
      if(valid.valid!==true||valid.candidate!==data.candidate)throw new ControlError('network-access.invalid_candidate');
      state.networkCandidates=data;state.reviewedCandidate=null;renderPage();
    }catch(error){state.networkCandidates=null;state.reviewedCandidate=null;toast('failed','error',{code:safeCode(error)});}
  };
  const mutate=async action=>{
    if(!state.networkCandidates)return;
    const snapshot=structuredClone(state.networkCandidates);
    if(!await dialog('reviewShared',h('pre',{},JSON.stringify(snapshot.records,null,2)),{danger:true}))return;
    await workflow('network-access.'+action,async()=>{const result=await bridge.execute(['--json','network-access',action,snapshot.candidate,'--confirm'],{write:true,label:'network-access.'+action});const data=envelope(result,'network-access.'+action);state.networkCandidates=null;state.reviewedCandidate=null;state.snapshots.set('network-access.result',data);toast('finished');renderPage();});
  };
  return section('networkAccess',h('p',{class:'muted'},tx('reviewShared')),button('checkCandidates',check,'',!isLive()),state.networkCandidates?rawDetails(state.networkCandidates):null,h('div',{class:'actions'},button('repair',()=>mutate('repair'),'primary',!state.networkCandidates),button('reapply',()=>mutate('reapply'),'',!state.networkCandidates),button('rollback',()=>mutate('rollback'),'',!state.networkCandidates)),...viewStatus('network-access.status'),rawDetails(state.snapshots.get('network-access.result')));
}
function dnsTool(){
  const profile=select('dns-profile',['default','cloudflare-doh','cloudflare-dot','cloudflare-udp'],'default'),domain=input('dns-domain','example.com',{autocomplete:'off'});
  return section('dns',field('profile',profile),h('div',{class:'actions'},button('save',()=>action(['dns','set',profile.value],{after:()=>readMachine(['dns','status'],'dns.status')}),'',!isLive()),button('apply',()=>action(['dns','apply'],{confirm:true,after:enterPage}),'',!isLive())),field('testDomain',domain),button('test',()=>privateTool(['dns','test',domain.value],false),'',!isLive()),...viewStatus('dns.status'));
}
function warpTool(){
  const file=input('warp-file','',{type:'file',accept:'.conf,.txt',onChange:async event=>{
    const item=event.target.files[0];event.target.value='';if(!item)return;
    await workflow('warp.import',async()=>{if(item.size>65536)throw new ControlError('warp.input_limit');const text=new TextDecoder('utf-8',{fatal:true}).decode(await item.arrayBuffer());checkExit(await privatePayload(bridge,text,'tmp',path=>['warp','import-file',path]));toast('finished');},{confirm:true});
  }});
  return section('warp',field('wireguardFile',file),h('div',{class:'actions'},button('refresh',()=>privateTool(['warp','status'],false),'',!isLive()),button('enable',()=>action(['warp','enable'],{confirm:true}),'',!isLive()),button('disable',()=>action(['warp','disable'],{confirm:true}),'',!isLive()),button('ruleMode',()=>action(['warp','rule']),'',!isLive()),button('globalMode',()=>action(['warp','global'],{confirm:true}),'',!isLive()),button('apply',()=>action(['warp','apply'],{confirm:true}),'',!isLive()),button('test',()=>privateTool(['warp','test'],false),'',!isLive())));
}
async function privateTool(args,write=true,confirm=false){
  if(write){await workflow(args.slice(0,2).join('.'),async()=>{state.privateOutput=(await command(args)).stdout;renderPage();},{confirm});}
  else try{state.privateOutput=stringify(await readHuman(args,{privateRead:true}));renderPage();}catch(error){state.privateOutput='';toast('failed','error',{code:safeCode(error)});}
}
function mcpTool(){
  const bind=input('mcp-bind','127.0.0.1'),port=input('mcp-port',9099,{type:'number',min:1,max:65535});
  return section('mcp',h('p',{class:'muted'},tx('mcpHelp')),h('div',{class:'form-grid'},field('bind',bind),field('port',port)),h('div',{class:'actions'},button('refresh',()=>privateTool(['mcp','status'],false),'',!isLive()),button('enable',()=>action(['mcp','enable',bind.value,port.value],{confirm:true}),'',!isLive()),button('disable',()=>action(['mcp','disable']),'',!isLive()),button('start',()=>action(['mcp','start']),'',!isLive()),button('stop',()=>action(['mcp','stop']),'',!isLive()),button('revealSecret',()=>privateTool(['mcp','secret'],false),'',!isLive()),button('rotateSecret',()=>privateTool(['mcp','rotate-secret'],true,true),'',!isLive())));
}
function backupTool(){
  const password=input('backup-password','',{type:'password',autocomplete:'new-password'}),content=h('textarea',{id:'backup-content',autocomplete:'off',spellcheck:false});
  return section('backup',field('backupPassword',password),field('backupData',content),h('div',{class:'actions'},button('exportBackup',()=>workflow('backup.export',async()=>{
    if(!hasFeature('backup_payload_v1'))throw new ControlError('backup.private_payload_unsupported');
    const result=checkExit(await privatePayload(bridge,JSON.stringify({password:password.value}),'tmp',path=>['backup','export-payload',path]));password.value='';downloadText('MagicNet.encrypted.backup',result.stdout);renderPage();
  }),'',!isLive()),button('restoreBackup',()=>workflow('backup.restore',async()=>{
    if(!hasFeature('backup_payload_v1'))throw new ControlError('backup.private_payload_unsupported');
    checkExit(await privatePayload(bridge,JSON.stringify({password:password.value,archive_base64:content.value.trim()}),'tmp',path=>['backup','restore-payload',path]));password.value='';content.value='';toast('finished');
  },{confirm:true}),'danger',!isLive())));
}
function captureTool(){
  const kind=select('capture-kind',['tls','gotls','nspr','pcap'],'tls'),seconds=input('capture-seconds',15,{type:'number',min:1,max:120}),pid=input('capture-pid','all'),uid=input('capture-uid','all'),iface=input('capture-interface','');
  return section('ecapture',h('p',{class:'muted'},tx('ecaptureHelp')),h('div',{class:'form-grid'},field('type',kind),field('seconds',seconds),field('pid',pid),field('uid',uid)),field('interface',iface),h('div',{class:'actions'},button('refresh',()=>privateTool(['ecapture','status'],false),'',!isLive()),button('capture',()=>privateTool(kind.value==='pcap'?['ecapture','pcap',seconds.value,iface.value]:['ecapture',kind.value,seconds.value,pid.value,uid.value],true,true),'primary',!isLive())));
}
function networkTool(){return section('network',networkForm(state.snapshots.get('network.status')),h('div',{class:'actions'},button('hotspot',()=>action(['hotspot','reconcile'],{after:refreshOverview}),'',!isLive()),button('support',()=>privateTool(['support','bundle']),'',!isLive()),button('topology',()=>privateTool(['sysroute','snapshot'],false),'',!isLive())));}

const initialRoute=location.hash.slice(1);
if(pages.some(([id])=>id===initialRoute)||initialRoute==='groups')state.route=initialRoute;
renderShell();setLocale(locale);
document.getElementById('skip').dataset.i18n='skip';translate();
if(bridge.native||bridge.sessionKey)connect();

// This read-only handle permits deterministic contract tests without production fixtures.
export {bridge,state,enterPage,renderPage};
