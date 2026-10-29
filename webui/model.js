import {ControlError} from './bridge.js';
export const utf8Length = value => new TextEncoder().encode(value).length;
export function normalizeSource(raw) {
  const value = raw.trim();
  if (!value || /[\s\\\u0000-\u001f\u007f]/u.test(value) || /%(?![a-f0-9]{2})/i.test(value)) throw new ControlError('source.invalid_url');
  const match = /^https:\/\/([^/?#]+)([^#]*)(?:#.*)?$/i.exec(value);
  if (!match || match[1].includes('@')) throw new ControlError('source.https_required');
  const authority = new URL('https://' + match[1] + '/');
  if (!authority.hostname || authority.username || authority.password || authority.port === '0') throw new ControlError('source.invalid_host');
  let suffix = match[2]; if (!suffix || suffix[0] === '?') suffix = '/' + suffix;
  suffix = suffix.replace(/[^\x00-\x7f]/gu, ch => Array.from(new TextEncoder().encode(ch), byte => '%' + byte.toString(16).toUpperCase().padStart(2,'0')).join(''));
  return 'https://' + authority.host.toLowerCase() + suffix;
}
export function sourcePreview(text) {
  const lines = text.split(/\r\n|\r|\n/).map(s => s.trim()).filter(Boolean);
  const unique = [], seen = new Set(), rows = [];
  let invalid = 0, duplicates = 0, fragments = 0, http = 0;
  for (let index = 0; index < lines.length; index++) {
    const raw = lines[index];
    let url, host = '', status = 'invalid';
    if (/^http:/i.test(raw)) http++;
    try {
      url = normalizeSource(raw); host = new URL(url).hostname;
      if (raw.includes('#')) fragments++;
      if (seen.has(url)) { status = 'duplicate'; duplicates++; }
      else { seen.add(url); unique.push(url); status = unique.length > 5 ? 'over-limit' : 'ok'; }
    } catch { invalid++; }
    rows.push({index:index+1,status,host});
  }
  return {raw:lines.length, valid:lines.length-invalid, unique, rows, invalid, duplicates, fragments,http,
    overLimit:Math.max(0,unique.length-5), canSave:invalid === 0 && unique.length >= 1 && unique.length <= 5};
}
const OWNERS = new Set(['active','none','stale','pending','unknown']);
const STAGES = new Set(['validate','fetch','parse','convert','merge','check','activate','complete','unknown']);
const OUTCOMES = new Set(['running','committed','rolled_back','recovery_pending','interrupted','unknown']);
const ERRORS = new Set('none input_invalid source_limit url_policy dns_failed tls_failed download_timeout download_failed response_too_large cache_untrusted format_unsupported converter_unavailable conversion_failed semantic_incomplete node_invalid empty_result merge_failed config_invalid activation_failed rollback_failed interrupted unknown'.split(' '));
export function validateSubscription(data, inspect = false, batchFeature = false) {
  const fail = () => { throw new ControlError('machine.subscription_invalid'); };
  if (!data || typeof data !== 'object' || !['remote_url','local_file'].includes(data.source?.mode) || !Number.isSafeInteger(data.source?.configured_count) || data.source.configured_count < 0 || data.source.configured_count > 5) fail();
  if (data.source.mode === 'local_file' && data.source.configured_count !== 1) fail();
  if (!data.update || !OWNERS.has(data.update.owner) || typeof data.update.lock_present !== 'boolean' || typeof data.update.transaction_pending !== 'boolean') fail();
  if (data.update.running !== undefined && data.update.running !== (data.update.owner === 'active' ? true : ['none','stale'].includes(data.update.owner) ? false : null)) fail();
  if (!data.last || typeof data.last.result !== 'string' || typeof data.last.phase !== 'string') fail();
  if (batchFeature) {
    if (!Object.hasOwn(data.last,'batch')) fail();
    const b = data.last.batch;
    if (b !== null) {
      if (b?.schema !== 1 || typeof b.generation_id !== 'string' || !b.generation_id || b.generation_id !== data.last.generation_id || !OUTCOMES.has(b.outcome) || !Number.isSafeInteger(b.requested_count) || !Number.isSafeInteger(b.unique_count) || b.unique_count < 1 || b.unique_count > 5 || b.requested_count < b.unique_count || !Array.isArray(b.sources) || b.sources.length !== b.unique_count || !ERRORS.has(b.error_code) || !['none','selector_replay_failed'].includes(b.warning_code)) fail();
      b.sources.forEach((s,index) => {
        if (s.index !== index + 1 || !STAGES.has(s.stage) || !['fresh','cached','failed','not_attempted','not_applicable'].includes(s.fetch_result) || !['success','not_needed','failed','not_attempted','unknown'].includes(s.convert_result) || !ERRORS.has(s.error_code)) fail();
        for (const key of ['parsed_count','imported_count','filtered_count','duplicate_count']) if (s[key] !== null && (!Number.isSafeInteger(s[key]) || s[key] < 0)) fail();
      });
    }
  }
  if (inspect) {
    const c = data.configuration;
    if (!c || !Array.isArray(c.sing_box_urls) || typeof c.user_agent !== 'string' || !Array.isArray(c.filters) || c.filters.some(f => typeof f !== 'string') || !Array.isArray(data.source_usage)) fail();
    if (data.source.mode === 'remote_url' && c.sing_box_urls.length !== data.source.configured_count) fail();
    if (data.source.mode === 'local_file' && (c.sing_box_urls.length || data.source_usage.length)) fail();
    try { if (c.sing_box_urls.some(u => typeof u !== 'string' || normalizeSource(u) !== u) || new Set(c.sing_box_urls).size !== c.sing_box_urls.length) fail(); } catch { fail(); }
  }
  return data;
}
export const validCounter = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
export async function usageRows(data) {
  if (data.source.mode === 'local_file') return [{index:1,local:true,state:'unknown'}];
  const rows = [];
  for (let index = 0; index < data.configuration.sing_box_urls.length; index++) {
    const url = data.configuration.sing_box_urls[index];
    const id = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url))), b => b.toString(16).padStart(2,'0')).join('');
    const candidates = data.source_usage.filter(m => m?.id === id);
    const metadata = candidates.length === 1 && candidates[0].index === index + 1 && candidates[0].hostname === new URL(url).hostname ? candidates[0] : null;
    let state = ['fresh','cached'].includes(metadata?.state) ? metadata.state : 'unknown';
    if (data.last.result !== 'success' && state === 'fresh') state = 'cached';
    if (data.update.transaction_pending || data.update.owner === 'active') state = 'unknown';
    const up = state !== 'unknown' ? validCounter(metadata.upload_bytes) : null;
    const down = state !== 'unknown' ? validCounter(metadata.download_bytes) : null;
    const total = state !== 'unknown' ? validCounter(metadata.total_bytes) : null;
    const used = up !== null && down !== null ? validCounter(up + down) : null;
    const expire = metadata?.expire_epoch;
    rows.push({index:index+1,host:new URL(url).hostname,state,used,total,
      remaining:total > 0 && used !== null ? Math.max(0,total-used) : null,
      percent:total > 0 && used !== null ? Math.min(100,100*used/total) : null,
      expires:Number.isSafeInteger(expire) && expire > 0 && expire <= 253402300799 ? expire : null});
  }
  return rows;
}
export class Draft {
  constructor(initial = '') { this.value = initial; this.baseline = initial; this.revision = 0; this.loaded = false; this.readSequence = 0; }
  get dirty() { return this.value !== this.baseline; }
  edit(value) { this.value = value; this.revision++; }
  snapshot() { return {value:this.value,revision:this.revision}; }
  accept(value, submitted = null) {
    const shouldReplace = submitted ? this.revision === submitted.revision && this.value === submitted.value : !this.dirty;
    this.baseline = value; this.loaded = true;
    if (shouldReplace) this.value = value;
  }
  reset() { this.value = this.baseline; this.revision++; }
}
export function sourceEditorVisible(draft, configuredCount, explicitlyOpen = false) {
  // A later draft remains reviewable when an earlier submission changes the
  // committed source count. Manual collapse only applies to a clean draft.
  return explicitlyOpen || draft.dirty || configuredCount == null || configuredCount === 0;
}
export function normalizeFilters(text) {
  const words = text.split(/\r\n|\r|\n/).map(x => x.trim()).filter(Boolean), seen = new Set(), out = [];
  for (const word of words) {
    if (utf8Length(word) > 64 || /[\x00-\x1f\x7f]/.test(word)) throw new ControlError('filter.invalid');
    const key = word.replace(/[A-Z]/g, x => x.toLowerCase());
    if (!seen.has(key)) {seen.add(key);out.push(word);}
  }
  if (out.length > 32) throw new ControlError('filter.limit');
  return out;
}
export function validateUserAgent(value) {
  value = value.trim();
  if (utf8Length(value) > 256 || /[\x00-\x1f\x7f]/.test(value)) throw new ControlError('user_agent.invalid');
  return value;
}
export function parseArgv(text) {
  const args = []; let part = '', quote = '', escape = false, started = false;
  for (const ch of text) {
    if (escape) {part += ch;escape = false;started = true;continue;}
    if (ch === '\\' && quote !== "'") {escape = true;continue;}
    if (quote) {if (ch === quote) quote = ''; else part += ch;started = true;continue;}
    if (ch === '"' || ch === "'") {quote = ch;started = true;continue;}
    if (/\s/.test(ch)) {if(started){args.push(part);part='';started=false;}continue;}
    if (';|&><`$\0'.includes(ch)) throw new ControlError('terminal.shell_syntax_rejected');
    part += ch;started = true;
  }
  if (quote || escape) throw new ControlError('terminal.unclosed_quote');
  if(started)args.push(part);
  return args;
}
