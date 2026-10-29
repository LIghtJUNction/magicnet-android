/* Native ownership outlives UI timeouts. Nothing in this adapter evaluates user code. */
export class ControlError extends Error {
  constructor(code, details = {}) { super(code); this.code = code; Object.assign(this, details); }
}
const CLI = '/data/adb/modules/MagicNet/cli';
const MAX_UNITS = 8388608, MAX_EVENTS = 65536;
export class OutputCollector {
  constructor() { this.stdout = ''; this.stderr = ''; this.events = 0; this.units = 0; this.overflow = false; }
  add(stream, chunk) {
    this.events++;
    if (this.overflow) return;
    if (typeof chunk !== 'string') { this.overflow = true; this.stdout = this.stderr = ''; return; }
    this.units += chunk.length;
    if (this.events > MAX_EVENTS || this.units > MAX_UNITS) {
      this.overflow = true; this.stdout = this.stderr = ''; return;
    }
    this[stream] += chunk;
  }
}
export const quoteArgument = value => "'" + String(value).replaceAll("'", "'\\''") + "'";
export function envelope(result, command) {
  if (!result || !Number.isInteger(result.exit_code) || typeof result.stdout !== 'string') throw new ControlError('bridge.invalid_result');
  let message;
  try { message = JSON.parse(result.stdout); } catch { throw new ControlError('machine.invalid_json'); }
  if (!message || message.schema !== 1 || typeof message.ok !== 'boolean' || message.command !== command) throw new ControlError('machine.invalid_envelope');
  if (result.exit_code !== 0 || !message.ok) {
    const code = message.error?.code;
    throw new ControlError(typeof code === 'string' && /^[a-z0-9_.-]{1,100}$/i.test(code) ? code : 'machine.command_failed');
  }
  if (!message.data || typeof message.data !== 'object' || Array.isArray(message.data)) throw new ControlError('machine.invalid_data');
  return message.data;
}
export class Bridge extends EventTarget {
  constructor() {
    super(); this.token = null; this.capabilities = null; this.writing = null; this.readers = 0;
    this.native = typeof globalThis.ksu?.exec === 'function' || typeof globalThis.MagicNetNative?.exec === 'function';
    this.mode = this.native ? 'native' : 'preview'; this.sequence = 0;
    this.instance = Array.from(crypto.getRandomValues(new Uint32Array(2)),n=>n.toString(36)).join('_');
    this.sessionKey = new URLSearchParams(location.hash.slice(1)).get('session');
    if(this.sessionKey)history.replaceState(null,'',location.pathname+location.search+'#overview');
  }
  signal() { this.dispatchEvent(new Event('change')); }
  async connect() {
    if (!this.native) {
      if (!['127.0.0.1', '[::1]', 'localhost'].includes(location.hostname)) throw new ControlError('bridge.loopback_required');
      if(!this.sessionKey)throw new ControlError('bridge.session_key_required');
      const response = await fetch('/api/session?key='+encodeURIComponent(this.sessionKey), {cache:'no-store', credentials:'same-origin'});
      if (!response.ok) throw new ControlError('bridge.session_unavailable');
      const session = await response.json();
      if (typeof session.token !== 'string' || session.token.length < 16) throw new ControlError('bridge.invalid_session');
      this.token = session.token; this.sessionKey = null; this.mode = 'http';
    }
    try {
      this.capabilities = envelope(await this.execute(['--json','capabilities']), 'machine.capabilities');
      if (this.capabilities.machine_schema !== 1 || !Array.isArray(this.capabilities.commands) || !Array.isArray(this.capabilities.features)) throw new ControlError('machine.incompatible');
      this.signal(); return this.capabilities;
    } catch (e) { this.capabilities = null; this.signal(); throw e; }
  }
  async machine(args, command, options = {}) {
    if (this.capabilities && !this.capabilities.commands.includes(command)) throw new ControlError('machine.unsupported');
    return envelope(await this.execute(['--json', ...args], options), command);
  }
  execute(args, {write = false, timeout = 30000, label = '', privateRead = false} = {}) {
    if (this.mode === 'preview') return Promise.reject(new ControlError('bridge.preview'));
    if (!Array.isArray(args) || args.length > 256 || args.some(a => typeof a !== 'string' || a.includes('\0'))) return Promise.reject(new ControlError('bridge.invalid_arguments'));
    if (write && this.writing) return Promise.reject(new ControlError('operation.busy', {operation_id:this.writing.id}));
    if (!write && this.readers >= 4) return Promise.reject(new ControlError('operation.read_limit'));
    const id = 'ui_' + Date.now().toString(36) + '_' + this.instance + '_' + (++this.sequence).toString(36);
    const owner = {id, label, start:Date.now(), state:'running', privateRead};
    if (write) this.writing = owner; else this.readers++;
    this.signal();
    return new Promise((resolve, reject) => {
      let callerDone = false, exited = false;
      const output = new OutputCollector();
      const callback = '__magicnet_' + id;
      const timer = setTimeout(() => {
        if (callerDone) return;
        callerDone = true; owner.state = 'unknown'; this.signal();
        reject(new ControlError('operation.timeout', {operation_id:id, running:true}));
      }, timeout);
      const done = (code, extra = {}) => {
        if (exited) return;
        exited = true; clearTimeout(timer);
        delete globalThis[callback];
        if (write && this.writing === owner) this.writing = null;
        if (!write) this.readers--;
        const result = {exit_code:Number(code), stdout:output.stdout, stderr:output.stderr, operation_id:id, ...extra};
        if (!callerDone) {
          callerDone = true;
          if (output.overflow) reject(new ControlError('bridge.output_limit'));
          else if (!Number.isInteger(result.exit_code)) reject(new ControlError('bridge.invalid_exit'));
          else resolve(result);
        }
        this.signal(); this.dispatchEvent(new CustomEvent('exit',{detail:{id,code:Number(code),label,late:owner.state === 'unknown'}}));
      };
      const fail = () => {
        if (!callerDone) { callerDone = true; reject(new ControlError('bridge.execution_failed')); }
        done(-1);
      };
      try {
        if (this.mode === 'http') {
          // Do not abort on a UI timeout: the authenticated server still owns the command.
          let polls = 0;
          const reconcile = () => {
            if(exited)return;
            polls++;
            fetch('/api/operation?id='+encodeURIComponent(id),{cache:'no-store',credentials:'same-origin',headers:{'X-MagicNet-Token':this.token}}).then(consumeResponse).catch(transportFailed);
          };
          const transportFailed = () => {
            if(exited)return;
            if(!write){fail();return;}
            owner.state='unknown';this.signal();
            // A disconnected HTTP response is not an executor exit.
            setTimeout(reconcile,Math.min(15000,1000+polls*1000));
          };
          const consumeResponse = async (response, initial = false) => {
            if(!response.ok) {
              if(initial && [400,401,403,409].includes(response.status)) {
                if(!callerDone){callerDone=true;reject(new ControlError('bridge.request_rejected'));}
                done(-1);return;
              }
              throw new ControlError('bridge.http_failed');
            }
            const reader=response.body?.getReader();let text='';
            if(reader){const decoder=new TextDecoder();for(;;){const {done:ended,value}=await reader.read();if(ended)break;text+=decoder.decode(value,{stream:true});if(text.length>MAX_UNITS*2){await reader.cancel();output.overflow=true;done(-1);return;}}text+=decoder.decode();}
            else text=await response.text();
            const result=JSON.parse(text);
            if(result.operation_id!==id)throw new ControlError('bridge.operation_mismatch');
            if(result.running===true){setTimeout(reconcile,Math.min(15000,1000+polls*1000));return;}
            output.add('stdout',result.stdout);output.add('stderr',result.stderr??'');
            done(result.exit_code,{operation_id:result.operation_id,receipt:result.receipt});
          };
          fetch('/api/command', {method:'POST', cache:'no-store', credentials:'same-origin',
            headers:{'Content-Type':'application/json','X-MagicNet-Token':this.token}, body:JSON.stringify({args,operation_id:id})})
            .then(response=>consumeResponse(response,true)).catch(transportFailed);
        } else if (typeof globalThis.MagicNetNative?.exec === 'function') {
          globalThis[callback] = (code, stdout = '', stderr = '', receipt = null) => { output.add('stdout',stdout); output.add('stderr',stderr); done(code,{receipt}); };
          globalThis.MagicNetNative.exec(JSON.stringify({executable:CLI,args,operation_id:id}), callback);
        } else if (typeof globalThis.ksu.spawn === 'function') {
          globalThis[callback] = {
            stdout:{emit:(event,data) => { if (event === 'data') output.add('stdout',data); }},
            stderr:{emit:(event,data) => { if (event === 'data') output.add('stderr',data); }},
            emit:(event,data) => { if (event === 'exit') done(data); else if (event === 'error') done(Number.isInteger(data?.exitCode) ? data.exitCode : -1); }
          };
          // KernelSU's documented spawn API receives a JSON argv array.
          globalThis.ksu.spawn(CLI, JSON.stringify(args), JSON.stringify({cwd:'/data/adb/modules/MagicNet'}), callback);
        } else {
          globalThis[callback] = (code, stdout = '', stderr = '') => { output.add('stdout',stdout); output.add('stderr',stderr); done(code); };
          globalThis.ksu.exec([CLI,...args].map(quoteArgument).join(' '), JSON.stringify({cwd:'/data/adb/modules/MagicNet'}), callback);
        }
      } catch { fail(); }
    });
  }
}
export function base64UTF8(text) {
  const bytes = new TextEncoder().encode(text);
  let value = ''; for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}
export async function privatePayload(bridge, text, namespace, consume, options = {}) {
  const bytes = new TextEncoder().encode(text);
  if (!bytes.length || bytes.length > 8 * 1024 * 1024) throw new ControlError('payload.size_limit');
  const name = 'ui-' + crypto.getRandomValues(new Uint32Array(3)).join('-') + '.data';
  let created = false, consumed = false;
  try {
    const create = await bridge.execute(['webui','payload','create',namespace,name],{write:true,label:'payload.create',timeout:15000});
    if (create.exit_code !== 0) throw new ControlError('payload.create_failed');
    const path = create.stdout.trim();
    const nativePath=/^\/data\/adb\/modules\/MagicNet\/[A-Za-z0-9_./-]+$/.test(path);
    if (!(bridge.mode==='native'?nativePath:nativePath||/^\/[A-Za-z0-9_./-]+$/.test(path))) throw new ControlError('payload.invalid_path');
    if (path.split('/').some(p => p === '..') || !path.endsWith('/' + name)) throw new ControlError('payload.invalid_path');
    created = true;
    for (let offset = 0; offset < bytes.length; offset += 12288) {
      const chunk = bytes.subarray(offset,offset + 12288);
      let binary = ''; for (const byte of chunk) binary += String.fromCharCode(byte);
      const append = await bridge.execute(['webui','payload','append',namespace,name,btoa(binary)],{write:true,label:'payload.append',timeout:15000});
      if (append.exit_code !== 0) throw new ControlError('payload.append_failed');
    }
    const args = typeof consume === 'function' ? consume(path,name) : ['webui','payload',consume,name];
    const result = await bridge.execute(args,{write:true,label:options.label || 'payload.apply',timeout:options.timeout || 120000});
    consumed = true; return result;
  } finally {
    if (created && !bridge.writing) {
      const clean = await bridge.execute(['webui','payload','remove',namespace,name],{write:true,label:'payload.cleanup',timeout:15000}).catch(() => null);
      if (!clean || clean.exit_code !== 0) bridge.dispatchEvent(new CustomEvent('warning',{detail:{code:'payload.cleanup_unconfirmed'}}));
    }
    if(created && !consumed && bridge.writing)bridge.dispatchEvent(new CustomEvent('warning',{detail:{code:'payload.cleanup_pending'}}));
  }
}
