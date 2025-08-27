const consoleLogs = [];
const consoleLogKeys = new Set();
let renderConsole = () => {};
let renderCE = () => {};
function addConsoleLog(level, args, extra){
  if(!liveConsole) return;
  const msg = args.map(a => {
    try { return typeof a === 'string' ? a : JSON.stringify(a); }
    catch(_e){ return String(a); }
  }).join(' ');
  let stack = extra && extra.stack;
  let source = extra && extra.source;
  let line = extra && extra.line;
  let col = extra && extra.col;
  if (!stack){ try{ stack = new Error().stack; }catch(_e){} }
  if (stack){
    const lines = String(stack).split('\n');
    for (const l of lines){
      const m = l.match(/(https?:\/\/[^):]+):(\d+):(\d+)/);
      if (m){
        if (!source) source = m[1];
        if (!line) line = m[2];
        if (!col) col = m[3];
        break;
      }
    }
  }
  const key = `${level}|${msg}|${source||''}|${line||''}|${col||''}|${stack||''}`;
  if (consoleLogKeys.has(key)) return;
  consoleLogKeys.add(key);
  const rec = { id: Date.now().toString(36)+Math.random().toString(36).slice(2), ts: Date.now(), time: new Date().toISOString(), level, message: msg, stack, source, line, col };
  ringPush(consoleLogs, rec);
  try{ if (globalThis.TREventBus) globalThis.TREventBus.emit({ type:`console:${level}`, message: msg, stack, source, line, col, ts: rec.ts }); }catch(_e){}
  try { renderConsole(); } catch(_e){}
  try { renderCE(); } catch(_e){}
}
(function(){
  ['log','error','warn'].forEach(level=>{
    const orig = globalThis.console[level];
    globalThis.console[level] = (...args)=>{ addConsoleLog(level, args); if(typeof orig==='function'){ try{ orig.apply(globalThis.console,args); }catch(_e){} } };
  });
})();

if (typeof window !== 'undefined' && window.addEventListener){
  window.addEventListener('error', ev=>{
    try{ addConsoleLog('error', [ev.message], { stack: ev.error && ev.error.stack, source: ev.filename, line: ev.lineno, col: ev.colno }); if(ev.error) ev.error.__trLogged=true; }catch(_e){}
    try{ if (globalThis.TREventBus) globalThis.TREventBus.emit({ type:'error:js', message:ev.message, stack:ev.error && ev.error.stack, source:ev.filename, line:ev.lineno, col:ev.colno, ts: Date.now() }); }catch(_e){}
  });
  window.addEventListener('unhandledrejection', ev=>{
    let msg = ''; let stack = ''; const r = ev.reason;
    if (r && typeof r === 'object'){
      msg = r.message || JSON.stringify(r);
      stack = r.stack;
      try{ r.__trLogged = true; }catch(_e){}
    } else msg = String(r);
    try{ addConsoleLog('error', [msg], { stack }); }catch(_e){}
    try{ if (globalThis.TREventBus) globalThis.TREventBus.emit({ type:'error:promise', message:msg, stack, ts: Date.now() }); }catch(_e){}
  });
}

function scanChunksAndTs(files){
  const findings = [];
  const secretPatterns = [
    /api[_-]?key/ig,
    /token/ig,
    /secret/ig,
    /password/ig
  ];
  const endpointRx = /\bhttps?:\/\/[^\s'"<>]+/ig;
  const ipRx = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const domainRx = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/ig;
  function extractJsonObjects(text){
    const results = [];
    function walk(segment){
      let i = 0;
      while(i < segment.length){
        const ch = segment[i];
        if (ch === '{'){
          const end = matchBrace(segment, i);
          if (end){
            const obj = segment.slice(i, end);
            if (/:/.test(obj)){ results.push(obj); walk(obj.slice(1, -1)); }
            i = end; continue;
          } else break;
        } else if (ch === '"' || ch === "'" || ch === '`'){
          i = skipString(segment, i);
          continue;
        } else if (ch === '/' && segment[i+1] === '/'){
          const n = segment.indexOf('\n', i+2);
          if (n === -1) break; i = n; continue;
        } else if (ch === '/' && segment[i+1] === '*'){
          const n = segment.indexOf('*/', i+2);
          if (n === -1) break; i = n + 2; continue;
        }
        i++;
      }
    }
    function skipString(str, start){
      const q = str[start];
      let i = start + 1;
      while(i < str.length){
        if (str[i] === '\\'){ i += 2; continue; }
        if (str[i] === q) return i + 1;
        i++;
      }
      return str.length;
    }
    function matchBrace(str, start){
      let depth = 1;
      let i = start + 1;
      let q = null;
      while(i < str.length){
        const ch = str[i];
        if (q){
          if (ch === '\\'){ i += 2; continue; }
          if (ch === q) q = null;
        } else {
          if (ch === '"' || ch === "'" || ch === '`') q = ch;
          else if (ch === '/' && str[i+1] === '/'){
            const n = str.indexOf('\n', i+2); if (n === -1) return str.length; i = n; continue;
          } else if (ch === '/' && str[i+1] === '*'){
            const n = str.indexOf('*/', i+2); if (n === -1) return str.length; i = n + 2; continue;
          } else if (ch === '{') depth++;
          else if (ch === '}'){ depth--; if (depth === 0) return i + 1; }
        }
        i++;
      }
      return null;
    }
    walk(text);
    return results;
  }
  for (const [name, content] of Object.entries(files || {})){
    if (!/\.ts$|\.js$|chunk/i.test(name)) continue;
    for (const rx of secretPatterns){
      let m; while ((m = rx.exec(content))){ findings.push({ file:name, type:'secret', match:m[0] }); }
      rx.lastIndex = 0;
    }
    let m;
    while ((m = endpointRx.exec(content))){ findings.push({ file:name, type:'endpoint', match:m[0] }); }
    endpointRx.lastIndex = 0;
    while ((m = ipRx.exec(content))){ findings.push({ file:name, type:'ip', match:m[0] }); }
    ipRx.lastIndex = 0;
    while ((m = domainRx.exec(content))){
      const start = m.index;
      const prev = content.slice(Math.max(0, start - 8), start);
      if (/https?:\/\//i.test(prev)) continue;
      findings.push({ file:name, type:'domain', match:m[0] });
    }
    domainRx.lastIndex = 0;
  for (const obj of extractJsonObjects(content)){
      findings.push({ file:name, type:'json', match:obj });
    }
  }
  return findings;
}

function createGlobalViewer(win, baseNames){
  win = win || (typeof window !== 'undefined' ? window : global);
  const doc = win.document;
  if (!doc || !doc.createElement || !doc.body) return null;

  let baseline = new Set(baseNames || []);
  if (!baseNames){
    try {
      const iframe = doc.createElement('iframe');
      iframe.style.display = 'none';
      doc.body.appendChild(iframe);
      baseline = new Set(Object.getOwnPropertyNames(iframe.contentWindow));
      doc.body.removeChild(iframe);
    } catch(_e) {}
  }

  const container = doc.createElement('div');
  Object.assign(container.style, { background:'#1e1e1e', color:'#fff', padding:'4px' });
  const output = doc.createElement('pre');
  Object.assign(output.style, {
    whiteSpace:'pre-wrap',
    maxHeight:'200px',
    overflow:'auto',
    background:'#1e1e1e',
    color:'#fff',
    padding:'4px'
  });

  const seen = new Set(baseline);

  const addBtn = name => {
    if (seen.has(name)) return;
    seen.add(name);
    const btn = doc.createElement('button');
    const value = win[name];
    const type = typeof value;
    const desc = Object.getOwnPropertyDescriptor(win, name) || {};
    let label = type;
    if (type !== 'function' && desc.writable === false) label = 'const';
    btn.textContent = type === 'function' ? `${name} (function)` : `${name} (${label})`;
    Object.assign(btn.style, {
      margin:'2px',
      background:'#333',
      color:'#fff',
      border:'1px solid #555',
      cursor:'pointer'
    });
    btn.addEventListener('click', () => {
      try {
        const v = win[name];
        if (typeof v === 'function') {
          let res;
          try { res = v(); } catch(fnErr){ res = fnErr; }
          output.textContent = String(res);
        } else if (v && typeof v === 'object') {
          const showObject = obj => {
            output.innerHTML = '';
            Reflect.ownKeys(obj).forEach(key => {
              const val = obj[key];
              const t2 = typeof val;
              const propBtn = doc.createElement('button');
              propBtn.textContent = t2 === 'function' ? `${String(key)} (method)` : `${String(key)} (${t2})`;
              Object.assign(propBtn.style, {
                margin:'2px',
                background:'#333',
                color:'#fff',
                border:'1px solid #555',
                cursor:'pointer'
              });
              propBtn.addEventListener('click', () => {
                try {
                  if (typeof val === 'function') {
                    let r;
                    try { r = val.call(obj); } catch(e){ r = e; }
                    output.textContent = String(r);
                  } else if (val && typeof val === 'object') {
                    showObject(val);
                  } else {
                    output.textContent = JSON.stringify(val, null, 2);
                  }
                } catch(e){
                  output.textContent = 'Error: ' + e.message;
                }
              });
              output.appendChild(propBtn);
            });
          };
          showObject(v);
        } else {
          output.textContent = JSON.stringify(v, null, 2);
        }
      } catch (e) {
        output.textContent = 'Error: ' + e.message;
      }
    });
    container.appendChild(btn);
  };

  const scan = () => {
    try { Object.getOwnPropertyNames(win).forEach(addBtn); } catch(_e){}
  };
  scan();
  win.setInterval && win.setInterval(scan, 1000);

  win.__TR_GV_ADDERS = win.__TR_GV_ADDERS || [];
  win.__TR_GV_ADDERS.push(addBtn);

  const origDefineProperty = Object.defineProperty;
  if (!origDefineProperty.__TR_GV_WRAPPED__) {
    const wrapper = function(obj, prop, desc){
      if (obj === win) {
        const name = String(prop);
        (win.__TR_GV_ADDERS || []).forEach(cb => cb(name));
      }
      return origDefineProperty.apply(this, arguments);
    };
    wrapper.__TR_GV_WRAPPED__ = true;
    Object.defineProperty = wrapper;
  }

  return { container, output };
}

function analyzeCodeSymbols(code){
  const symbols = [];
  const add = (name, type) => { if (name) symbols.push({ name, type }); };

  const varRx = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)/g;
  let m;
  while ((m = varRx.exec(code))) add(m[1], 'variable');

  const fnRx = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
  while ((m = fnRx.exec(code))) add(m[1], 'function');

  const objMethodRx = /([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?(?:function\s*)?\(/g;
  while ((m = objMethodRx.exec(code))) add(m[1], 'method');

  const objShorthandRx = /(?:\{|,)\s*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*{/g;
  while ((m = objShorthandRx.exec(code))) add(m[1], 'method');

  const classRx = /class\s+[A-Za-z_$][\w$]*\s*{([\s\S]*?)}/g;
  let cls;
  while ((cls = classRx.exec(code))){
    const body = cls[1];
    const classMethodRx = /(?:^|;|\s)([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*{/g;
    let mm;
    while ((mm = classMethodRx.exec(body))) add(mm[1], 'method');
  }

  const seen = new Set();
  return symbols.filter(s => {
    const key = `${s.type}:${s.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

if (typeof module !== 'undefined' && module.exports){
  module.exports.scanChunksAndTs = scanChunksAndTs;
  module.exports.createGlobalViewer = createGlobalViewer;
  module.exports.analyzeCodeSymbols = analyzeCodeSymbols;
}

// ==UserScript==
// @name         Pentest Toolkit++ (Files/JS/Crawler/Versions/API Fuzzer/Buckets, Shadow DOM, Progress+Lines)
// @namespace    https://tu-namespace
// @version      2.3
// @description  Files probe, JS secret hunter (dominios+scope), domain-scoped crawler, version detector (headers/filenames/comments/JS) con dedupe y líneas, API fuzzer, bucket checker desde rutas reales. UI aislada (Shadow DOM). CSV con file+line. Barras de progreso para todos.
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setClipboard
// @connect      *
// @run-at       document-idle
// ==/UserScript==
if (typeof window !== 'undefined') (function () {
  'use strict';

  /* ============================
     CONFIG
  ============================ */
  const UI = { Z: 2147483647 };
  const FILES = { AUTO_START: false, MAX_CONCURRENCY: 4, REQ_DELAY_MS: 200, TIMEOUT_MS: 8000, MAX_GEN: 200 };
  const JS    = { AUTO_START: false, MAX_CONCURRENCY: 3, TIMEOUT_MS: 12000, FETCH_DELAY_MS: 120 };
  const CRAWL = { MAX_PAGES: 180, MAX_CONCURRENCY: 3, DELAY_MS: 150, TIMEOUT_MS: 10000, MAX_QUERY_LEN: 2000 };
  const VERS  = { TIMEOUT_MS: 9000, BYTES_HEAD: 3500, MAX_CONCURRENCY: 5 };
  const FUZZ  = { MAX_CONCURRENCY: 4, TIMEOUT_MS: 9000, SAFE_MODE: true, DELAY_MS: 120 };
  const BUCKS = { TIMEOUT_MS: 9000, JS_DETECT_MAX_CONC: 6 };
  const DEBUG = { TIMEOUT_MS: 8000, DEFAULT_MAX_MB: 5 };

  /* ============================
     Shadow DOM host (anti-CSS)
  ============================ */
  const host = document.createElement('div');
  Object.assign(host.style, { all: 'initial', position: 'fixed', inset: 'auto 0 0 auto', zIndex: String(UI.Z) });
  document.documentElement.appendChild(host);
  const root = host.attachShadow({ mode: 'open' });

  /* ============================
     Utils
  ============================ */
  const unique = arr => Array.from(new Set(arr));
  const errorLog = [];
  let renderErrors = () => {};
  function logError(e){
    const msg = e && e.message ? e.message : String(e);
    errorLog.push({ time: new Date().toISOString(), message: msg });
    try { addConsoleLog('error', ['TamperRecon error:', e]); } catch(_e) {}
    try { renderErrors(); } catch(_e) {}
  }
  const sameOrigin = url => { try { return new URL(url, location.origin).origin === location.origin; } catch(e){ logError(e); return false; } };
  const mkAbs = p => { try { return new URL(p, location.href).href; } catch(e){ logError(e); return null; } };
  const escCSV = s => `"${String(s ?? '').replace(/"/g, '""')}"`;
  const escHTML = s => String(s ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
  const highlightEnc = text => {
    let out = text;
    if (typeof atob === 'function') {
      out = out.replace(/\b[A-Za-z0-9+/]{20,}={0,2}\b/g, b64 => {
        // avoid treating pure hex as base64
        if (/^(?:[0-9a-fA-F]{2})+$/.test(b64)) return b64;
        try {
          const dec = atob(b64);
          if (/[^\x20-\x7E]/.test(dec)) return b64;
          return `<span class="ptk-b64" title="${escHTML(dec)}">${b64}</span>`;
        } catch (_e) {
          return b64;
        }
      });
    }
    out = out.replace(/\b(?:[0-9a-fA-F]{2}){4,}\b/g, hex => {
      try {
        const bytes = hex.match(/.{2}/g).map(b => parseInt(b,16));
        const dec = String.fromCharCode(...bytes);
        const printable = !/[^\x20-\x7E]/.test(dec);
        const title = printable ? ` title="${escHTML(dec)}"` : '';
        return `<span class="ptk-hex"${title}>${hex}</span>`;
      } catch (_e) {
        return hex;
      }
    });
    return out;
  };
  const family = status => (status>=200&&status<300)?'2':(status>=300&&status<400)?'3':(status>=400&&status<500)?'4':(status>=500)?'5':'other';
  const famColor = f => f==='2'? '#22c55e' : f==='3'? '#facc15' : (f==='4'||f==='5')? '#ef4444' : '#cbd5e1';
  const nowStr = () => new Date().toISOString().replace(/[:.]/g,'-');
  const clip = text => { try { if (typeof GM_setClipboard==='function') GM_setClipboard(text, 'text'); } catch(e){ logError(e); } };
  const looksLike404 = txt => {
    const t = String(txt||'').slice(0,400).toLowerCase();
    return /(404|not found|page not found|p[aá]gina no encontrada|no encontrado|does not exist)/.test(t);
  };
  const withTimeout = (p, ms) => Promise.race([
    p,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
  ]);
  const IGNORE_EXT = /\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff|woff2?|eot|ttf|otf|css|map|mp4|webm|mp3|wav|ogg|m4a|mov|avi)(\?|#|$)/i;
  const PAGE_LIKE  = /\.(?:html?|php|aspx?|jsp|cfm|md|txt|xml|json)(\?|#|$)/i;
  const SCRIPT_LIKE= /\.(?:js)(\?|#|$)/i;
  const EVENT_TYPES = Object.freeze({
    NET: 'net:*',
    WS: 'ws:*',
    SSE: 'sse:*',
    PM: 'pm:*',
    CODEC: 'codec:*',
    CRYPTO: 'crypto:*',
    CONSOLE: 'console:*',
    ERROR_JS: 'error:js'
  });

  function csvDownload(filename, header, rows) {
    const csv = header.join(',') + '\n' + rows.map(r => header.map(h => escCSV(r[h])).join(',')).join('\n');
    const blob = new Blob([csv], { type:'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
  }
  function textDownload(filename, text){
    const blob = new Blob([text], { type:'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
  }
  function redact(str, {head=32, tail=32} = {}){
    const s = String(str ?? '');
    return s.length <= head + tail ? s : s.slice(0, head) + '…' + s.slice(-tail);
  }
  function truncateBytes(x, max = 4096){
    try{
      if (x == null) return x;
      if (typeof x === 'string'){
        if (typeof TextEncoder !== 'undefined' && typeof TextDecoder !== 'undefined'){
          const enc = new TextEncoder().encode(x);
          if (enc.length <= max) return x;
          return new TextDecoder().decode(enc.slice(0, max));
        }
        if (typeof Buffer !== 'undefined'){
          const buf = Buffer.from(x);
          return buf.length <= max ? x : buf.slice(0, max).toString();
        }
        return x.slice(0, max);
      }
      if (Array.isArray(x) || ArrayBuffer.isView(x)){
        return x.length <= max ? x : x.slice(0, max);
      }
    }catch(_e){}
    return x;
  }
  function csvFromObjects(rows, cols){
    return [cols.join(',') , ...rows.map(r => cols.map(c => escCSV(r[c])).join(','))].join('\n');
  }
  function saveCSV(rows, filename){
    if (!Array.isArray(rows) || !rows.length) return;
    const cols = Object.keys(rows[0]);
    csvDownload(filename, cols, rows);
  }
  function saveJSON(obj, filename){
    textDownload(filename, JSON.stringify(obj, null, 2));
  }
  function ringPush(arr, item, max = 2000){
    arr.push(item);
    if (arr.length > max) arr.splice(0, arr.length - max);
  }
  function rowsToMarkdown(rows, cols){
    if (!rows.length) return '';
    const head = `|${cols.join('|')}|`;
    const sep = `|${cols.map(()=> '---').join('|')}|`;
    const body = rows.map(r => '|' + cols.map(c => String(r[c]||'').replace(/\|/g,'\\|')).join('|') + '|').join('\n');
    return head + '\n' + sep + '\n' + body;
  }
  function renderChunked(list, container, rowFn, emptyHtml){
    container.innerHTML='';
    if(!list.length){ if(emptyHtml) container.innerHTML=emptyHtml; return; }
    let i=0;
    function step(){
      const end=Math.min(i+50,list.length);
      for(; i<end; i++) container.appendChild(rowFn(list[i], i));
      if(i<list.length) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function makeRingBuffer(name, max = 2000){
    const host = (typeof location !== 'undefined' && location.hostname) ? location.hostname : 'global';
    const key = `rb_${host}_${name||'default'}`;
    let buf = [];
    try{
      if (typeof GM_getValue === 'function'){
        buf = JSON.parse(GM_getValue(key, '[]')) || [];
      }
    }catch(_e){}
    function save(){
      if (typeof GM_setValue === 'function'){
        try{ GM_setValue(key, JSON.stringify(buf)); }catch(_e){}
      }
    }
    return {
      push(item){ buf.push(item); if (buf.length > max) buf.splice(0, buf.length - max); save(); },
      get(i){ return buf[i]; },
      all(){ return buf.slice(); },
      clear(){ buf.length = 0; save(); },
      size(){ return buf.length; }
    };
  }

  function ebPreview(val, max = 80){
    try{
      if (val === undefined || val === null) return '';
      if (typeof val === 'string') return val.slice(0, max);
      if (typeof val === 'object'){
        if (ArrayBuffer.isView(val)) return Array.from(val.slice ? val.slice(0, max) : new Uint8Array(val).slice(0, max)).join(',');
        return JSON.stringify(val).slice(0, max);
      }
      return String(val).slice(0, max);
    }catch(_e){ return ''; }
  }
  function ebSize(val){
    try{
      if (val === undefined || val === null) return 0;
      if (typeof val === 'string') return val.length;
      if (typeof val === 'object'){
        if (ArrayBuffer.isView(val) || val instanceof ArrayBuffer) return val.byteLength || val.length || 0;
        return JSON.stringify(val).length;
      }
      return String(val).length;
    }catch(_e){ return 0; }
  }
  function ebHeadersToObj(h){
    const o = {};
    try{
      if (!h) return o;
      if (typeof h.forEach === 'function') h.forEach((v,k)=>o[k]=v);
      else if (Array.isArray(h)) h.forEach(([k,v])=>o[k]=v);
      else if (typeof h === 'object') Object.keys(h).forEach(k=>o[k]=h[k]);
    }catch(_e){}
    return o;
  }
  function ebParseHeaders(str){
    const o = {};
    if (!str) return o;
    try{
      str.trim().split(/\r?\n/).forEach(line=>{
        const idx = line.indexOf(':');
        if (idx>0){ const k=line.slice(0,idx).trim().toLowerCase(); const v=line.slice(idx+1).trim(); o[k]=v; }
      });
    }catch(_e){}
    return o;
  }
  function ebIsJSON(str){
    try{ JSON.parse(str); return true; }catch(_e){ return false; }
  }
  function ebIsJWT(str){
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str||'');
  }
  function ebToString(val){
    try{
      if(val==null) return '';
      if(typeof val==='string') return val;
      if(ArrayBuffer.isView(val) || val instanceof ArrayBuffer){
        const arr = val instanceof ArrayBuffer ? new Uint8Array(val) : val;
        return Array.from(arr).join(',');
      }
      return JSON.stringify(val);
    }catch(_e){ try{ return String(val); }catch(__e){ return ''; } }
  }

  // Event schemas:
  // net:fetch/xhr {type,phase,method,url,status,ok,ms,reqHeaders,resHeaders,reqBody,resBody,ts}
  // ws:* {type,url,data,code?,reason?,ts}
  // sse:message {type,url,event,data,ts}
  // pm:* {type,origin?,target?,channel?,data,ts}
  // codec:* {type,inputPreview,outputPreview,length,isJSON?,isJWT?,ts}
  // crypto:* {type,alg?,keyPreview?,ivPreview?,length?,sample?,ts}
  // console:*/error:js {type,message,stack?,source?,line?,col?,ts}

  const TREventBus = (()=>{
    let subId = 0;
    const subs = [];
    const buffers = {
      net:    makeRingBuffer('net',2000),
      ws:     makeRingBuffer('ws',2000),
      sse:    makeRingBuffer('sse',2000),
      pm:     makeRingBuffer('pm',2000),
      codec:  makeRingBuffer('codec',2000),
      crypto: makeRingBuffer('crypto',2000),
      console:makeRingBuffer('console',2000)
    };
    let evtCount=0, lastTick=0, sampling=false, sampleCount=0;
    const SAMPLE_THRESHOLD=200;
    function match(pat, type){
      if (pat === '*' ) return true;
      if (pat.endsWith('*')) return type.startsWith(pat.slice(0,-1));
      return pat === type;
    }
    function emit(ev){
      try{ ev.ts = ev.ts || Date.now(); }catch(_e){}
      const now=Date.now();
      if(now-lastTick>1000){ lastTick=now; evtCount=0; sampleCount=0; sampling=false; }
      evtCount++;
      if(evtCount>SAMPLE_THRESHOLD){ sampling=true; sampleCount++; if(sampleCount%5!==0) return; }
      const root = (ev.type||'').split(':')[0];
      const buf = buffers[root];
      if (buf) buf.push(ev);
      subs.forEach(s=>{ if (match(s.type, ev.type) && (!s.filter || s.filter(ev))) try{ s.cb(ev); }catch(_e){} });
    }
    function subscribe(type, cb, filter){
      const id = ++subId; subs.push({id,type,cb,filter}); return id;
    }
    function unsubscribe(id){
      const i = subs.findIndex(s=>s.id===id); if (i>=0) subs.splice(i,1);
    }
    return { emit, subscribe, unsubscribe, buffers, get sampling(){ return sampling; } };
  })();
  globalThis.TREventBus = TREventBus;
  globalThis.TREventBuffers = TREventBus.buffers;
  function getBaseDomain(h){
    h = (h||'').toLowerCase();
    const parts = h.split('.').filter(Boolean);
    if (parts.length <= 2) return h;
    const twoLevel = new Set(['co.uk','org.uk','ac.uk','gov.uk','com.mx','org.mx','edu.mx','gob.mx','com.br','com.ar','com.au','co.jp','co.kr','com.tr','com.pl']);
    const last2 = parts.slice(-2).join('.');
    const last3 = parts.slice(-3).join('.');
    if (twoLevel.has(last2)) return parts.slice(-3).join('.');
    if (twoLevel.has(last3)) return parts.slice(-4).join('.');
    return last2;
  }
  function inScopeDomain(targetHost, mode, overrideBase){
    if (!targetHost) return false;
    const th = targetHost.toLowerCase();
    if (mode === 'all') return true;
    if (mode === 'origin') return th === location.hostname.toLowerCase();
    const baseHere = overrideBase ? overrideBase.toLowerCase() : getBaseDomain(location.hostname);
    const baseTgt  = overrideBase ? overrideBase.toLowerCase() : getBaseDomain(th);
    return baseHere === baseTgt;
  }
  function lineFromIndex(text, idx){
    if (idx <= 0) return 1;
    let n = 1;
    for (let i=0;i<idx;i++) if (text[i] === '\n') n++;
    return n;
  }
  function getAllGlobals(){
    const out = {};
    const props = Object.getOwnPropertyNames(window);
    props.forEach(k=>{
      try{
        const v = window[k];
        if (v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'){
          out[k] = v;
        } else if (typeof v === 'function'){
          out[k] = v.toString();
        } else if (typeof v === 'object'){
          try {
            out[k] = JSON.stringify(v);
          } catch (e){
            logError(e);
            out[k] = String(v);
          }
        } else {
          out[k] = String(v);
        }
      }catch(e){ logError(e); }
    });
    return out;
  }

  const eventLogs = [];
  const runtimeLogs = [];
  let rsRender;
  let updateRuntimeBadge = ()=>{};
  let runtimeNotify = ()=>{};
  let runtimeAlerted = false;
  let capturePostMessage = false;
  function logEvent(type, details){
    eventLogs.push(Object.assign({ time: new Date().toISOString(), type }, details));
  }
  function addRuntimeLog(rec){
    if(!liveGlobals){
      const t = rec.type || '';
      if(t==='global' || t==='localStorage' || t==='sessionStorage' || t==='cookie') return;
    }
    ringPush(runtimeLogs, rec);
    logEvent('runtime', rec);
    updateRuntimeBadge();
    if (typeof rsRender === 'function') rsRender();
    if (typeof runtimeNotify === 'function') runtimeNotify();
  }

  const netLogs = [];
  let netRender = ()=>{};
  let netPaused = false;
  let netSeq = 0;
  function hostFromUrl(u){ try{ return new URL(u, location.href).host; }catch(_e){ return ''; } }
  function headersObj(h){
    const out={};
    try{
      if(h && typeof h.forEach==='function') h.forEach((v,k)=>out[k]=v);
      else if(h && typeof h==='object') Object.entries(h).forEach(([k,v])=>out[k]=v);
    }catch(_e){}
    return out;
  }
  function parseXHRHeaders(str){
    const out={};
    try{ str.trim().split(/\r?\n/).forEach(line=>{ const i=line.indexOf(':'); if(i>0){ const k=line.slice(0,i).trim().toLowerCase(); const v=line.slice(i+1).trim(); out[k]=v; } }); }catch(_e){}
    return out;
  }
  function addNetLog(rec){
    if(netPaused || !liveNet) return;
    if(globalThis.TREventBus && globalThis.TREventBus.sampling && Math.random()<0.8) return;
    rec.id = ++netSeq;
    ringPush(netLogs, rec);
    logEvent('network', rec);
    updateRuntimeBadge();
    try{ if(globalThis.TREventBus) globalThis.TREventBus.emit({ type:'network', data:rec, ts:Date.now() }); }catch(_e){}
    try{ netRender(); }catch(_e){}
  }

  const msgLogs = [];
  let msgRender = ()=>{};
  let msgPaused = false;
  let msgSeq = 0;
  const codecLogs = [];
  let codecRender = ()=>{};
  let codecSeq = 0;
  const cryptoLogs = [];
  let cryptoRender = ()=>{};
  let cryptoSeq = 0;
  function addCodecLog(rec){
    if(!liveCodec) return;
    if(globalThis.TREventBus && globalThis.TREventBus.sampling && Math.random()<0.8) return;
    rec.id = ++codecSeq;
    if(rec.inputPreview===undefined) rec.inputPreview = ebPreview(rec.input,100);
    if(rec.outputPreview===undefined) rec.outputPreview = ebPreview(rec.output,100);
    if(rec.inputFull===undefined) rec.inputFull = ebToString(rec.input);
    if(rec.outputFull===undefined) rec.outputFull = ebToString(rec.output);
    ringPush(codecLogs, rec);
    logEvent('codec', rec);
    updateRuntimeBadge();
    try{ codecRender(); }catch(_e){}
  }
  function addCryptoLog(rec){
    if(!liveCrypto) return;
    if(globalThis.TREventBus && globalThis.TREventBus.sampling && Math.random()<0.8) return;
    rec.id = ++cryptoSeq;
    if(rec.keyPreview !== undefined) rec.keyPreview = redact(rec.keyPreview);
    if(rec.ivPreview !== undefined) rec.ivPreview = redact(rec.ivPreview);
    if(rec.sample !== undefined) rec.sample = redact(rec.sample);
    ringPush(cryptoLogs, rec);
    logEvent('crypto', rec);
    updateRuntimeBadge();
    try{ cryptoRender(); }catch(_e){}
  }
  function addMsgLog(rec){
    if(msgPaused || !liveMsg) return;
    if(globalThis.TREventBus && globalThis.TREventBus.sampling && Math.random()<0.8) return;
    rec.id = ++msgSeq;
    ringPush(msgLogs, rec);
    logEvent('messaging', rec);
    updateRuntimeBadge();
    try{ msgRender(); }catch(_e){}
  }
  function handlePmEvent(ev){
    const type = (ev.type||'').split(':')[1] || '';
    const rec = {
      ts: ev.ts || Date.now(),
      channel: ev.channel || 'postMessage',
      type,
      origin: ev.origin || '',
      target: ev.target || '',
      size: ev.size || 0,
      preview: ev.data || ''
    };
    addMsgLog(rec);
  }
  let pmSubId = 0;
  function updatePmSubscription(){
    try{
      if(!globalThis.TREventBus) return;
      if(liveMsg){
        if(!pmSubId){
          if(globalThis.TREventBuffers && globalThis.TREventBuffers.pm) globalThis.TREventBuffers.pm.all().forEach(handlePmEvent);
          pmSubId = globalThis.TREventBus.subscribe('pm:*', handlePmEvent);
        }
      } else if(pmSubId){
        globalThis.TREventBus.unsubscribe(pmSubId);
        pmSubId = 0;
      }
    }catch(_e){}
  }

  function handleCryptoEvent(ev){
    const type = (ev.type||'').split(':')[1] || '';
    addCryptoLog({
      ts: ev.ts || Date.now(),
      type,
      alg: ev.alg || '',
      keyPreview: ev.keyPreview || '',
      ivPreview: ev.ivPreview || '',
      length: ev.length || 0,
      sample: ev.sample || ''
    });
  }
  let cryptoSubId = 0;
  function updateCryptoSubscription(){
    try{
      if(!globalThis.TREventBus) return;
      if(liveCrypto){
        if(!cryptoSubId){
          if(globalThis.TREventBuffers && globalThis.TREventBuffers.crypto) globalThis.TREventBuffers.crypto.all().forEach(handleCryptoEvent);
          cryptoSubId = globalThis.TREventBus.subscribe('crypto:*', handleCryptoEvent);
        }
      } else if(cryptoSubId){
        globalThis.TREventBus.unsubscribe(cryptoSubId);
        cryptoSubId = 0;
      }
    }catch(_e){}
  }

  const origFetch = window.fetch;
  if (origFetch) window.fetch = function(input, init){
    if(netPaused) return origFetch.call(this, input, init);
    const start=performance.now();
    const ts=Date.now();
    const url=typeof input==='string'?input:(input&&input.url);
    const method=(init&&init.method)||(input&&input.method)||'GET';
    const reqHeaders=headersObj((init&&init.headers)||(input&&input.headers));
    let reqBody=init&&init.body;
    if(typeof reqBody==='string') reqBody=truncateBytes(reqBody);
    return origFetch.call(this,input,init).then(resp=>{
      const rec={ts,type:'fetch',method,url,host:hostFromUrl(url),status:resp.status,ms:Math.round(performance.now()-start),size:0,reqHeaders,reqBody};
      try{ rec.resHeaders=headersObj(resp.headers); }catch(_e){}
      return resp.clone().arrayBuffer().then(buf=>{
        rec.size=buf.byteLength;
        try{ rec.resBody=truncateBytes(new TextDecoder().decode(buf)); }catch(_e){}
        addNetLog(rec); return resp; });
    }).catch(err=>{ addNetLog({ts,type:'fetch',method,url,host:hostFromUrl(url),status:0,ms:Math.round(performance.now()-start),size:0,reqHeaders,reqBody,error:String(err)}); throw err; });
  };

  const OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function(){
    const xhr = new OrigXHR();
    let url='', method='GET', start=0, ts=0; const reqHeaders={}; let reqBody;
    const finalize=()=>{
      if(netPaused) return;
      const rec={ts,type:'xhr',method,url,host:hostFromUrl(url),status:xhr.status,ms:Math.round(performance.now()-start),size:(xhr.response? (xhr.response.length||0):0),reqHeaders,reqBody};
      try{ rec.resHeaders=parseXHRHeaders(xhr.getAllResponseHeaders()); }catch(_e){}
      try{ rec.resBody=truncateBytes(xhr.responseText); }catch(_e){}
      addNetLog(rec);
    };
    xhr.addEventListener('loadend', finalize);
    const origOpen=xhr.open; xhr.open=function(m,u,a){ method=m; url=u; return origOpen.call(xhr,m,u,a); };
    const origSend=xhr.send; xhr.send=function(body){ if(netPaused) return origSend.call(xhr, body); start=performance.now(); ts=Date.now(); reqBody=truncateBytes(body); return origSend.call(xhr, body); };
    const origSetRequestHeader=xhr.setRequestHeader; xhr.setRequestHeader=function(k,v){ reqHeaders[k]=v; return origSetRequestHeader.call(xhr,k,v); };
    return xhr;
  };

  const OrigWS = window.WebSocket;
  window.WebSocket = new Proxy(OrigWS, {
    construct(target, args){
      const ws = new target(...args);
      const url = args[0];
      const host = hostFromUrl(url);
      ws.addEventListener('message', ev=>{ if(!netPaused) addNetLog({ts:Date.now(),type:'ws',method:'recv',url,host,status:0,ms:0,size:(ev.data&&ev.data.length)||0,resBody:truncateBytes(String(ev.data))}); });
      ws.addEventListener('close', ev=>{ if(!netPaused) addNetLog({ts:Date.now(),type:'ws',method:'close',url,host,status:ev.code,ms:0,size:0}); });
      const s = ws.send; ws.send=function(data){ if(!netPaused) addNetLog({ts:Date.now(),type:'ws',method:'send',url,host,status:0,ms:0,size:(data&&data.length)||0,reqBody:truncateBytes(String(data))}); return s.call(ws,data); };
      return ws;
    }
  });

  const OrigES = window.EventSource;
  window.EventSource = function(url, cfg){
    const es = new OrigES(url, cfg);
    const host = hostFromUrl(url);
    es.addEventListener('message', ev=>{ if(!netPaused) addNetLog({ts:Date.now(),type:'sse',method:ev.type||'message',url,host,status:0,ms:0,size:(ev.data&&ev.data.length)||0,resBody:truncateBytes(String(ev.data))}); });
    es.addEventListener('error', ()=>{ if(!netPaused) addNetLog({ts:Date.now(),type:'sse',method:'error',url,host,status:0,ms:0,size:0}); });
    return es;
  };
  const origEval = window.eval;
  window.eval = function(str){
    if (typeof str === 'string') addRuntimeLog({ type:'eval', code:str });
    return origEval.call(this, str);
  };
  const origFunction = window.Function;
  window.Function = new Proxy(origFunction, {
    apply(target, thisArg, args){
      const body = args.length && typeof args[args.length-1]==='string' ? args.join(',') : '';
      if (body) addRuntimeLog({ type:'Function', code:body });
      return Reflect.apply(target, thisArg, args);
    },
    construct(target, args){
      const body = args.length && typeof args[args.length-1]==='string' ? args.join(',') : '';
      if (body) addRuntimeLog({ type:'Function', code:body });
      return Reflect.construct(target, args);
    }
  });
  const origSetTimeout = window.setTimeout;
  window.setTimeout = function(handler, timeout, ...args){
    if (typeof handler === 'string') addRuntimeLog({ type:'setTimeout', code:handler });
    return origSetTimeout.call(this, handler, timeout, ...args);
  };

  /* ============================
     Styles (scoped)
  ============================ */
  const style = document.createElement('style');
  style.textContent = `
    :host{ all: initial }
    .ptk-wrap{position:fixed;background:#0b1220;color:#e8f1ff;border:1px solid #233;border-radius:12px;
      font:12px system-ui;box-shadow:0 12px 28px rgba(0,0,0,.35);z-index:${UI.Z}}
    .ptk-wrap *{color:#e8f1ff}
    .ptk-btn{background:#1f2a44;color:#e8f1ff;border:1px solid #3b82f6;padding:6px 10px;border-radius:8px;cursor:pointer;display:inline-block}
    .ptk-btn:disabled{opacity:.6;cursor:not-allowed}
    .ptk-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0}
    .ptk-tab{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:5px 8px;cursor:pointer}
    .ptk-tab.active{background:#1f2a44;border-color:#3b82f6}
    .ptk-box{border:1px dashed #324;border-radius:10px;padding:10px;margin:8px 0}
    .ptk-row{margin:6px 0;border-top:1px dashed #324;padding-top:6px}
    .ptk-hdr{font-weight:700}
    .ptk-flex{display:flex;gap:8px;align-items:center;justify-content:space-between}
    .ptk-grid{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .ptk-link{color:#93c5fd;text-decoration:none}
    .ptk-pillbar{height:6px;background:#1f2a44;border-radius:8px;overflow:hidden}
    .ptk-bar{height:6px;width:0%}
    .ptk-code{opacity:.95;word-break:break-all}
    .ptk-b64{background:#1f2937;cursor:help}
    .ptk-hex{background:#422006;cursor:help}
    .ptk-chip{background:#1f2a44;border:1px solid #334155;border-radius:6px;padding:2px 4px;font-size:10px;opacity:.8;margin-left:4px}
    input[type="number"],input[type="text"],select{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:4px 6px}
    label{opacity:.95}
  `;
  root.appendChild(style);

  /* ============================
     Panel + Tabs
  ============================ */
  const panel = document.createElement('div');
  panel.className = 'ptk-wrap';
  Object.assign(panel.style, { top:'12px', left:'12px', maxWidth:'960px', maxHeight:'72vh', overflow:'auto', padding:'12px', display:'none' });
  panel.innerHTML = `
    <div class="ptk-flex" style="margin-bottom:6px">
      <div class="ptk-hdr">Pentest Toolkit — ${location.hostname}</div>
      <div class="ptk-grid"><button id="ptk_toggle" class="ptk-btn">Ocultar</button></div>
    </div>
      <div class="ptk-tabs" id="top_tabs">
        <div class="ptk-tab" data-tab="discover">Discover</div>
        <div class="ptk-tab" data-tab="apis">APIs</div>
        <div class="ptk-tab" data-tab="security">Security</div>
        <div class="ptk-tab" data-tab="runtime">Runtime</div>
        <div class="ptk-tab active" data-tab="report">Report/Settings</div>
      </div>
      <div id="top_discover" style="display:none">
        <div class="ptk-tabs" id="tabs_discover">
          <div class="ptk-tab active" data-tab="files">Files (0)</div>
          <div class="ptk-tab" data-tab="js">JS Hunter (0)</div>
          <div class="ptk-tab" data-tab="crawler">Crawler (0)</div>
          <div class="ptk-tab" data-tab="debug">Source Maps / Debug Artefacts (0)</div>
        </div>
        <section id="tab_discover_files"></section>
        <section id="tab_discover_js" style="display:none"></section>
        <section id="tab_discover_crawler" style="display:none"></section>
        <section id="tab_discover_debug" style="display:none">
          <div class="ptk-row">
            <button id="dbg_list">Listar maps</button>
            <button id="dbg_fetch">Descargar y Demapear (≤5MB)</button>
            <button id="dbg_rescan">Re-escanear con JS Hunter</button>
            <button id="dbg_copy">Copiar JSON</button>
            <button id="dbg_csv">CSV</button>
            <label>Límite MB <input type="number" id="dbg_limit" style="width:60px" min="1"></label>
            <span id="dbg_status">En espera…</span>
          </div>
          <div id="dbg_results"></div>
        </section>
      </div>
      <div id="top_apis" style="display:none">
        <div class="ptk-tabs" id="tabs_apis">
          <div class="ptk-tab active" data-tab="openapi">OpenAPI/Swagger (0)</div>
          <div class="ptk-tab" data-tab="graphql">GraphQL (0)</div>
          <div class="ptk-tab" data-tab="cors">CORS Tester (0)</div>
          <div class="ptk-tab" data-tab="ratelimit">Rate-Limit Probe (0)</div>
          <div class="ptk-tab" data-tab="fuzzer">API Fuzzer (0)</div>
        </div>
        <section id="tab_apis_openapi"></section>
        <section id="tab_apis_graphql" style="display:none"></section>
        <section id="tab_apis_cors" style="display:none"></section>
        <section id="tab_apis_ratelimit" style="display:none"></section>
        <section id="tab_apis_fuzzer" style="display:none"></section>
      </div>
      <div id="top_security" style="display:none">
        <div class="ptk-tabs" id="tabs_security">
          <div class="ptk-tab active" data-tab="versions">Versions/Headers/Policies (0)</div>
          <div class="ptk-tab" data-tab="cookies">Cookies & Storage (0)</div>
          <div class="ptk-tab" data-tab="tls">TLS (0)</div>
          <div class="ptk-tab" data-tab="sw">SW & Cache (0)</div>
        </div>
        <section id="tab_security_versions"></section>
        <section id="tab_security_cookies" style="display:none"><div class="ptk-row">Placeholder</div></section>
        <section id="tab_security_tls" style="display:none"><div class="ptk-row">Placeholder</div></section>
        <section id="tab_security_sw" style="display:none"><div class="ptk-row">Placeholder</div></section>
      </div>
      <div id="top_runtime" style="display:none">
        <div class="ptk-tabs" id="tabs_runtime">
          <div class="ptk-tab active" data-tab="network"><span class="ptk-label">Network (0)</span><span class="ptk-chip"></span></div>
          <div class="ptk-tab" data-tab="messaging"><span class="ptk-label">Messaging (0)</span><span class="ptk-chip"></span></div>
          <div class="ptk-tab" data-tab="codecs"><span class="ptk-label">Codecs (0)</span><span class="ptk-chip"></span></div>
          <div class="ptk-tab" data-tab="crypto"><span class="ptk-label">Crypto (0)</span><span class="ptk-chip"></span></div>
          <div class="ptk-tab" data-tab="console"><span class="ptk-label">Console & Errors (0)</span><span class="ptk-chip"></span></div>
          <div class="ptk-tab" data-tab="globals"><span class="ptk-label">Globals/Vars (0)</span><span class="ptk-chip"></span></div>
        </div>
        <section id="tab_runtime_network"></section>
        <section id="tab_runtime_messaging" style="display:none">
          <div class="ptk-box">
            <div class="ptk-flex">
              <div class="ptk-hdr">Messaging</div>
              <div class="ptk-grid">
                <input id="msg_txt" class="ptk-input" placeholder="Texto" style="width:80px">
                <input id="msg_channel" class="ptk-input" placeholder="Canal" style="width:100px">
                <input id="msg_origin" class="ptk-input" placeholder="Origin" style="width:100px">
                <input id="msg_target" class="ptk-input" placeholder="Target" style="width:100px">
                <button id="msg_pause" class="ptk-btn">Pausar</button>
                <button id="msg_clear" class="ptk-btn">Clear</button>
                <button id="msg_json" class="ptk-btn">JSON</button>
                <button id="msg_csv" class="ptk-btn">CSV</button>
                <button id="msg_md" class="ptk-btn">Pinned MD</button>
              </div>
            </div>
            <div style="max-height:200px;overflow:auto">
              <table style="width:100%;border-collapse:collapse">
                <thead><tr><th>ts</th><th>canal/tipo</th><th>origin</th><th>target</th><th>size</th><th>preview</th><th>acciones</th></tr></thead>
                <tbody id="msg_rows"></tbody>
              </table>
            </div>
          </div>
        </section>
        <section id="tab_runtime_codecs" style="display:none"></section>
        <section id="tab_runtime_crypto" style="display:none"></section>
        <section id="tab_runtime_console" style="display:none"><div class="ptk-row">Placeholder</div></section>
        <section id="tab_runtime_globals" style="display:none"><div class="ptk-row">Placeholder</div></section>
      </div>
      <div id="top_report">
        <div class="ptk-tabs" id="tabs">
          <div class="ptk-tab active" data-tab="buckets">Cloud Buckets</div>
          <div class="ptk-tab" data-tab="hard">Hardening</div>
          <div class="ptk-tab" data-tab="console">Console</div>
          <div class="ptk-tab" data-tab="errors">Errors</div>
          <div class="ptk-tab" data-tab="settings">Settings</div>
        </div>
        <section id="tab_buckets"></section>
        <section id="tab_hard" style="display:none"></section>
        <section id="tab_console" style="display:none"></section>
        <section id="tab_errors" style="display:none"></section>
        <section id="tab_settings" style="display:none"></section>
      </div>
      `;
  root.appendChild(panel);

  const pill = document.createElement('div');
  pill.className = 'ptk-wrap';
  Object.assign(pill.style, { right:'12px', bottom:'12px', minWidth:'260px', padding:'8px 10px' });
  pill.innerHTML = `
    <div class="ptk-flex">
      <div class="ptk-hdr">Pentest Toolkit</div>
      <button id="pill_open" class="ptk-btn">Panel</button>
    </div>
    <div style="margin-top:6px">Files: <span id="pill_files_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_files_bar" class="ptk-bar" style="background:#38bdf8"></div></div>
    <div style="margin-top:6px">JS: <span id="pill_js_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_js_bar" class="ptk-bar" style="background:#22c55e"></div></div>
    <div style="margin-top:6px">Crawler: <span id="pill_crawl_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_crawl_bar" class="ptk-bar" style="background:#facc15"></div></div>
    <div style="margin-top:6px">Fuzzer: <span id="pill_fuzz_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_fuzz_bar" class="ptk-bar" style="background:#ef4444"></div></div>
    <div style="margin-top:6px">Versions: <span id="pill_ver_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_ver_bar" class="ptk-bar" style="background:#a78bfa"></div></div>
    <div style="margin-top:6px">Buckets: <span id="pill_bk_txt">—</span></div>
    <div class="ptk-pillbar"><div id="pill_bk_bar" class="ptk-bar" style="background:#60a5fa"></div></div>
  `;
  root.appendChild(pill);

  const btnToggle = panel.querySelector('#ptk_toggle');
  btnToggle.onclick = () => {
    const hide = panel.style.display !== 'none';
    panel.style.display = hide ? 'none' : '';
    btnToggle.textContent = hide ? 'Mostrar' : 'Ocultar';
  };
  pill.querySelector('#pill_open').onclick = () => {
    const hide = panel.style.display === 'none';
    panel.style.display = hide ? '' : 'none';
    btnToggle.textContent = hide ? 'Ocultar' : 'Mostrar';
  };
  const site = location.hostname || 'global';
  let liveNet = true, liveMsg = true, liveCodec = true, liveCrypto = true, liveConsole = true, liveGlobals = true;
  try{
    if(typeof GM_getValue==='function'){
      liveNet = GM_getValue(`${site}_live_net`, true);
      liveMsg = GM_getValue(`${site}_live_msg`, true);
      liveCodec = GM_getValue(`${site}_live_codec`, true);
      liveCrypto = GM_getValue(`${site}_live_crypto`, true);
      liveConsole = GM_getValue(`${site}_live_console`, true);
      liveGlobals = GM_getValue(`${site}_live_globals`, true);
    }
  }catch(_e){}
  function loadPins(key){
    try{ if(typeof GM_getValue==='function'){ const j=GM_getValue(`${site}_pin_${key}`,'[]'); return JSON.parse(j)||[]; } }catch(_e){}
    return [];
  }
  function savePins(key, arr){
    try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_pin_${key}`, JSON.stringify(arr)); }catch(_e){}
  }
  function isPinned(list, rec){ return list.some(r=>r.id===rec.id); }
  function togglePin(list, rec, btn, key){
    const idx=list.findIndex(r=>r.id===rec.id);
    if(idx>=0){ list.splice(idx,1); btn.textContent='Pin'; }
    else { list.push(rec); if(list.length>2000) list.splice(0,list.length-2000); btn.textContent='Unpin'; }
    savePins(key, list);
  }
  const netPins = loadPins('net');
  const msgPins = loadPins('msg');
  const cdPins = loadPins('codec');
  const cryptoPins = loadPins('crypto');
  const cePins = loadPins('console');
  const codecCfg = { btoa:false, text:false };
  try{
    if(typeof GM_getValue==='function'){
      codecCfg.btoa = GM_getValue(`${site}_codec_btoa`, false);
      codecCfg.text = GM_getValue(`${site}_codec_text`, false);
    }
  }catch(_e){}
  const topTabsEl = panel.querySelector('#top_tabs');
  function showTopTab(name){
    ['discover','apis','security','runtime','report'].forEach(t=>{
      const sec = panel.querySelector('#top_'+t);
      if (sec) sec.style.display = t===name ? '' : 'none';
      const btn = topTabsEl.querySelector(`.ptk-tab[data-tab="${t}"]`);
      if (btn) btn.classList.toggle('active', t===name);
    });
    try{ if (typeof GM_setValue === 'function') GM_setValue(`ptk_top_${site}`, name); }catch(_e){}
  }
  topTabsEl.addEventListener('click', ev=>{
    const t = ev.target && ev.target.closest('.ptk-tab');
    if (t) showTopTab(t.dataset.tab);
  });
  let savedTop = 'report';
  try{ if (typeof GM_getValue === 'function') savedTop = GM_getValue(`ptk_top_${site}`, savedTop); }catch(_e){}
  showTopTab(savedTop);

  function initTabs(prefix, list, wrap){
    const tabsEl = wrap.querySelector('.ptk-tabs');
    function show(name){
      list.forEach(t=>{
        const sec = wrap.querySelector('#tab_'+(prefix?prefix+'_':'')+t);
        if (sec) sec.style.display = t===name ? '' : 'none';
        const btn = tabsEl.querySelector(`.ptk-tab[data-tab="${t}"]`);
        if (btn) btn.classList.toggle('active', t===name);
      });
      try{ if (typeof GM_setValue === 'function') GM_setValue(`${site}_${prefix||'report'}_tab`, name); }catch(_e){}
    }
    tabsEl.addEventListener('click', ev=>{
      const t = ev.target && ev.target.closest('.ptk-tab');
      if (t) show(t.dataset.tab);
    });
    let saved = list[0];
    try{ if (typeof GM_getValue === 'function') saved = GM_getValue(`${site}_${prefix||'report'}_tab`, list[0]); }catch(_e){}
    show(saved);
    return show;
  }

  initTabs('', ['buckets','hard','console','errors','settings'], panel.querySelector('#top_report'));
  initTabs('discover', ['files','js','crawler','debug'], panel.querySelector('#top_discover'));
  initTabs('apis', ['openapi','graphql','cors','ratelimit','fuzzer'], panel.querySelector('#top_apis'));
  initTabs('security', ['versions','cookies','tls','sw'], panel.querySelector('#top_security'));
  const showRuntimeTab = initTabs('runtime', ['network','messaging','codecs','crypto','console','globals'], panel.querySelector('#top_runtime'));

  const reportTabsEl = panel.querySelector('#tabs');
  const runtimeNetTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="network"]');
  const runtimeMsgTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="messaging"]');
  const runtimeCodecTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="codecs"]');
  const runtimeCryptoTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="crypto"]');
  const runtimeConsoleTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="console"]');
  const runtimeGlobalsTab = panel.querySelector('#tabs_runtime .ptk-tab[data-tab="globals"]');
  const runtimeNetLabel = runtimeNetTab && runtimeNetTab.querySelector('.ptk-label');
  const runtimeMsgLabel = runtimeMsgTab && runtimeMsgTab.querySelector('.ptk-label');
  const runtimeCodecLabel = runtimeCodecTab && runtimeCodecTab.querySelector('.ptk-label');
  const runtimeCryptoLabel = runtimeCryptoTab && runtimeCryptoTab.querySelector('.ptk-label');
  const runtimeConsoleLabel = runtimeConsoleTab && runtimeConsoleTab.querySelector('.ptk-label');
  const runtimeGlobalsLabel = runtimeGlobalsTab && runtimeGlobalsTab.querySelector('.ptk-label');
  const runtimeNetChip = runtimeNetTab && runtimeNetTab.querySelector('.ptk-chip');
  const runtimeMsgChip = runtimeMsgTab && runtimeMsgTab.querySelector('.ptk-chip');
  const runtimeCodecChip = runtimeCodecTab && runtimeCodecTab.querySelector('.ptk-chip');
  const runtimeCryptoChip = runtimeCryptoTab && runtimeCryptoTab.querySelector('.ptk-chip');
  const runtimeConsoleChip = runtimeConsoleTab && runtimeConsoleTab.querySelector('.ptk-chip');
  const runtimeGlobalsChip = runtimeGlobalsTab && runtimeGlobalsTab.querySelector('.ptk-chip');
  const consoleTabBtn = reportTabsEl.querySelector('.ptk-tab[data-tab="console"]');
  const errorsTabBtn = reportTabsEl.querySelector('.ptk-tab[data-tab="errors"]');
  updateRuntimeBadge = function(){
    if (runtimeNetLabel) runtimeNetLabel.textContent = `Network (${runtimeLogs.length + netLogs.length})`;
    if (runtimeMsgLabel) runtimeMsgLabel.textContent = `Messaging (${msgLogs.length})`;
    if (runtimeCodecLabel) runtimeCodecLabel.textContent = `Codecs (${codecLogs.length})`;
    if (runtimeCryptoLabel) runtimeCryptoLabel.textContent = `Crypto (${cryptoLogs.length})`;
    if (runtimeConsoleLabel) runtimeConsoleLabel.textContent = `Console & Errors (${consoleLogs.length})`;
  };
  function updateLiveChips(){
    if(runtimeNetChip) runtimeNetChip.textContent = liveNet ? 'LIVE' : 'OFF';
    if(runtimeMsgChip) runtimeMsgChip.textContent = liveMsg ? 'LIVE' : 'OFF';
    if(runtimeCodecChip) runtimeCodecChip.textContent = liveCodec ? 'LIVE' : 'OFF';
    if(runtimeCryptoChip) runtimeCryptoChip.textContent = liveCrypto ? 'LIVE' : 'OFF';
    if(runtimeConsoleChip) runtimeConsoleChip.textContent = liveConsole ? 'LIVE' : 'OFF';
    if(runtimeGlobalsChip) runtimeGlobalsChip.textContent = liveGlobals ? 'LIVE' : 'OFF';
  }
  function updateConsoleBadge(){
    if (consoleTabBtn) consoleTabBtn.textContent = `Console (${consoleLogs.length})`;
  }
  function updateErrorBadge(){
    if (errorsTabBtn) errorsTabBtn.textContent = `Errors (${errorLog.length})`;
  }
  updateRuntimeBadge();
  updateConsoleBadge();
  updateErrorBadge();
  const tabConsole = panel.querySelector('#tab_console');
  renderConsole = function(){
    if (!tabConsole) return;
    tabConsole.innerHTML = consoleLogs.length ? '' : '<div class="ptk-row">No logs</div>';
    consoleLogs.forEach(log => {
      const div = document.createElement('div');
      div.className = 'ptk-row';
      div.textContent = `${log.time} [${log.level}] ${log.message}`;
      tabConsole.appendChild(div);
    });
    updateConsoleBadge();
  };
  renderConsole();

  const tabErrors = panel.querySelector('#tab_errors');
  renderErrors = function(){
    if (!tabErrors) return;
    tabErrors.innerHTML = errorLog.length ? '' : '<div class="ptk-row">No errors</div>';
    errorLog.forEach(err => {
      const div = document.createElement('div');
      div.className = 'ptk-row';
      div.textContent = `${err.time} - ${err.message}`;
      tabErrors.appendChild(div);
    });
    updateErrorBadge();
  };
  renderErrors();
  const tabSettings = panel.querySelector('#tab_settings');
  tabSettings.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-hdr">Live Capture</div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="live_net"> Network</label>
        <label><input type="checkbox" id="live_msg"> Messaging</label>
        <label><input type="checkbox" id="live_codec"> Codecs</label>
        <label><input type="checkbox" id="live_crypto"> Crypto</label>
        <label><input type="checkbox" id="live_console"> Console/Errors</label>
        <label><input type="checkbox" id="live_globals"> Globals</label>
      </div>
    </div>
  `;
  const liveRefs = {
    net: tabSettings.querySelector('#live_net'),
    msg: tabSettings.querySelector('#live_msg'),
    codec: tabSettings.querySelector('#live_codec'),
    crypto: tabSettings.querySelector('#live_crypto'),
    console: tabSettings.querySelector('#live_console'),
    globals: tabSettings.querySelector('#live_globals')
  };
  liveRefs.net.checked = liveNet;
  liveRefs.msg.checked = liveMsg;
  liveRefs.codec.checked = liveCodec;
  liveRefs.crypto.checked = liveCrypto;
  liveRefs.console.checked = liveConsole;
  liveRefs.globals.checked = liveGlobals;
  function persistLive(key, val){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_live_${key}`, val); }catch(_e){} }
  liveRefs.net.onchange = ()=>{ liveNet = liveRefs.net.checked; persistLive('net', liveNet); updateLiveChips(); };
  liveRefs.msg.onchange = ()=>{ liveMsg = liveRefs.msg.checked; persistLive('msg', liveMsg); updatePmSubscription(); updateLiveChips(); };
  liveRefs.codec.onchange = ()=>{ liveCodec = liveRefs.codec.checked; persistLive('codec', liveCodec); updateLiveChips(); };
  liveRefs.crypto.onchange = ()=>{ liveCrypto = liveRefs.crypto.checked; persistLive('crypto', liveCrypto); updateCryptoSubscription(); updateLiveChips(); };
  liveRefs.console.onchange = ()=>{ liveConsole = liveRefs.console.checked; persistLive('console', liveConsole); updateLiveChips(); };
  liveRefs.globals.onchange = ()=>{ liveGlobals = liveRefs.globals.checked; persistLive('globals', liveGlobals); updateLiveChips(); };
  updatePmSubscription();
  updateCryptoSubscription();
  updateLiveChips();
  runtimeNotify = function(){
    showTopTab('runtime');
    showRuntimeTab('network');
    if (!runtimeAlerted){
      runtimeAlerted = true;
      try{ addConsoleLog('log', ['Runtime secret found']); }catch(e){ logError(e); }
    }
  };

  /* ============================
     FILES (igual que antes, con CSV file/line)
  ============================ */
  const tabFiles = panel.querySelector('#tab_discover_files');
  const filesTabBtn = panel.querySelector('#tabs_discover .ptk-tab[data-tab="files"]');
  tabFiles.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Sensitive Files Probe</div>
        <div class="ptk-grid">
          <button id="sf_start" class="ptk-btn">Escanear</button>
          <button id="sf_pause" class="ptk-btn">Pausar</button>
          <button id="sf_clear" class="ptk-btn">Clear</button>
          <button id="sf_copy" class="ptk-btn">Copiar JSON</button>
          <button id="sf_csv" class="ptk-btn">CSV</button>
        </div>
      </div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="sf_useStatic" checked> Base estática</label>
        <label><input type="checkbox" id="sf_useHost" checked> Variantes por host</label>
        <label><input type="checkbox" id="sf_usePath" checked> Variantes por ruta</label>
        <label><input type="checkbox" id="sf_useDOM"> DOM links</label>
        <label><input type="checkbox" id="sf_prefixStatic"> Estáticos bajo ruta</label>
        <label><input type="checkbox" id="sf_prefixInter"> Prefijos intermedios</label>
        <label><input type="checkbox" id="sf_graphql" checked> GraphQL</label>
      </div>
      <div class="ptk-grid">
        Mostrar:
        <label><input type="checkbox" id="sf_show2" checked> 2xx</label>
        <label><input type="checkbox" id="sf_show3" checked> 3xx</label>
        <label><input type="checkbox" id="sf_show4" checked> 4xx</label>
        <label><input type="checkbox" id="sf_show5" checked> 5xx</label>
      </div>
      <div id="sf_counts" class="ptk-grid" style="opacity:.95">
        <span>2xx: <b id="sf_c2">0</b></span>
        <span>3xx: <b id="sf_c3">0</b></span>
        <span>4xx: <b id="sf_c4">0</b></span>
        <span>5xx: <b id="sf_c5">0</b></span>
        <span>Otros: <b id="sf_cOther">0</b></span>
      </div>
      <div id="sf_status" style="margin:6px 0">En espera…</div>
      <div id="sf_results"></div>
    </div>
  `;
  function getCurrentDir() {
    const p = location.pathname;
    if (p.endsWith('/')) return p;
    const i = p.lastIndexOf('/');
    return i >= 0 ? p.slice(0, i + 1) : '/';
  }
  function joinAtCurrent(path) { const dir = getCurrentDir(); const rel = String(path || '').replace(/^\/+/, ''); return (dir + rel).replace(/\/{2,}/g, '/'); }
  function getAllDirPrefixes() {
    const p = getCurrentDir().replace(/\/+$/,'/') || '/';
    const segs = p.split('/').filter(Boolean);
    const prefixes = ['/']; let acc = '';
    segs.forEach(s => { acc += '/' + s; prefixes.push(acc + '/'); });
    return unique(prefixes);
  }
  const staticPaths = [
    '/.env','/.env.local','/.env.production','/.env.prod','/.env.example',
    '/.git/HEAD','/.git/config','/.gitignore','/.gitlab-ci.yml','/.github/workflows/',
    '/.svn/entries','/.hg','/.bzr',
    '/.htpasswd','/.htaccess','/.DS_Store',
    '/wp-config.php','/wp-config.php.bak','/config.php','/config.php.bak',
    '/.ftpconfig','/ftpconfig','/sftp-config.json',
    '/.npmrc','/.yarnrc','/composer.json','/composer.lock',
    '/package.json','/package-lock.json','/yarn.lock',
    '/docker-compose.yml','/docker-compose.yaml','/docker-compose.dev.yml','/docker-compose.prod.yml',
    '/docker-compose.production.yml','/docker-compose.test.yml','/docker-compose.override.yml',
    '/docker-compose.ci.yml','/docker-compose.staging.yml','/Dockerfile','/.docker/config.json',
    '/.aws/credentials','/id_rsa','/.ssh/id_rsa','/.ssh/known_hosts',
    '/.git-credentials','/.ssh/config','/wp-config-sample.php','/config.yaml','/config.yml',
    '/settings.py','/localsettings.php','/sites/default/settings.php',
    '/db.sqlite','/database.sqlite','/debug.log','/storage/debug.log',
    '/swagger','/swagger.json','/openapi.json','/api-docs','/v3/api-docs',
    '/graphql','/actuator','/actuator/health','/metrics','/health',
    '/security.txt','/robots.txt','/sitemap.xml','/ads.txt',
    '/server-status','/server-info','/.babelrc','/.eslintrc','/.eslintrc.json',
    '/backup/','/backups/','/.backup/','/.backups/','/public_html/','/www/','/wwwroot/','/htdocs/'
  ];
  const archiveExts = ['.zip','.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.7z','.rar','.gz'];
  const commonSuffixes = ['', '-backup', '_backup', '-bak', '_bak', '.bak', '.old', '-latest', '-prod', '-production', '-stage', '-staging', '-dev', '-test'];
  const gqlBaseNames = ['graphql','api/graphql','v1/graphql','v2/graphql','gql','graph'];
  const gqlUINames   = ['graphiql','playground','altair','voyager'];
  const seedsFromHost = () => {
    const h = location.hostname.replace(/^www\./, '');
    return unique(['backup','backups','site','website','public_html','www','wwwroot','htdocs','code','app','build','dist','db','database','dump','sql','db_backup','full_backup', h, h.replace(/\./g,'_'), h.replace(/\./g,'-')]);
  };
  function seedsFromPath() {
    const segs = location.pathname.split('/').filter(Boolean).slice(-3);
    const sanitize = s => s.trim().replace(/[^a-zA-Z0-9._-]+/g, '-');
    const singles = [];
    segs.forEach(seg => { const s = sanitize(seg); if (s) { singles.push(s); singles.push(s.replace(/-/g,'_')); } });
    const combos = [];
    for (let i=1;i<=segs.length;i++){ const slice=segs.slice(0,i).map(sanitize).join('/'); if (slice) combos.push(slice); }
    return unique([...singles, ...combos]);
  }
  const makeArchiveVariants = (bases, limit) => {
    const out = [];
    for (const base of bases) for (const suf of commonSuffixes) for (const ext of archiveExts) {
      out.push(`/${base}${suf}${ext}`); if (out.length>=limit) return unique(out);
    }
    return unique(out);
  };
  function buildGraphQLEndpoints() {
    const list = [];
    gqlBaseNames.concat(gqlUINames).forEach(n => list.push('/'+n));
    seedsFromPath().forEach(base => gqlBaseNames.concat(gqlUINames).forEach(n => list.push(`/${base.replace(/^\/+/,'')}/${n}`)));
    gqlBaseNames.forEach(n => {
      list.push(`/${n}?query=${encodeURIComponent('{__typename}')}`);
      seedsFromPath().forEach(base => list.push(`/${base.replace(/^\/+/,'')}/${n}?query=${encodeURIComponent('{__typename}')}`));
    });
    return unique(list);
  }
  function collectDOMZips() {
    const urls = new Set();
    const extRx = /\.(zip|tar|tgz|tar\.gz|tbz2|tar\.bz2|tar\.xz|7z|rar|gz)(\?|#|$)/i;
    const nameRx = /\b(public_html|backup|backups|db|database|dump|wwwroot|htdocs)\b/i;
    document.querySelectorAll('[href],[src],[data]').forEach(n=>{
      ['href','src','data'].forEach(a=>{
        const v = n.getAttribute && n.getAttribute(a); if (!v) return;
        let abs; try { abs = new URL(v, location.origin).href; } catch(e){ logError(e); return; }
        if (!sameOrigin(abs)) return; if (extRx.test(abs) || nameRx.test(abs)) urls.add(abs);
      });
    });
    return Array.from(urls);
  }

  const tabElsF = {
    start: tabFiles.querySelector('#sf_start'),
    pause: tabFiles.querySelector('#sf_pause'),
    clear: tabFiles.querySelector('#sf_clear'),
    copy:  tabFiles.querySelector('#sf_copy'),
    csv:   tabFiles.querySelector('#sf_csv'),
    status:tabFiles.querySelector('#sf_status'),
    results:tabFiles.querySelector('#sf_results'),
    c2: tabFiles.querySelector('#sf_c2'),
    c3: tabFiles.querySelector('#sf_c3'),
    c4: tabFiles.querySelector('#sf_c4'),
    c5: tabFiles.querySelector('#sf_c5'),
    cOther: tabFiles.querySelector('#sf_cOther'),
    chk: {
      useStatic: tabFiles.querySelector('#sf_useStatic'),
      useHost: tabFiles.querySelector('#sf_useHost'),
      usePath: tabFiles.querySelector('#sf_usePath'),
      useDOM: tabFiles.querySelector('#sf_useDOM'),
      prefixStatic: tabFiles.querySelector('#sf_prefixStatic'),
      prefixInter: tabFiles.querySelector('#sf_prefixInter'),
      gql: tabFiles.querySelector('#sf_graphql'),
      show2: tabFiles.querySelector('#sf_show2'),
      show3: tabFiles.querySelector('#sf_show3'),
      show4: tabFiles.querySelector('#sf_show4'),
      show5: tabFiles.querySelector('#sf_show5')
    }
  };
  const pillFilesTxt = pill.querySelector('#pill_files_txt');
  const pillFilesBar = pill.querySelector('#pill_files_bar');

  const sf = { findings: [], session: 0, queue: [], inFlight: 0, idx: 0, done: 0, started: false, paused: false };
  function sfSetProgress(done,total){
    const pct = total ? Math.round(done/total*100) : 0;
    pillFilesTxt.textContent = total? `${done}/${total} • activos=${sf.inFlight}${sf.paused?' • PAUSADO':''}` : '—';
    pillFilesBar.style.width = pct+'%';
    pillFilesBar.style.background = pct>=100 ? '#22c55e' : '#38bdf8';
  }
  function sfUpdateStatus(){
    const total = sf.queue.length;
    tabElsF.status.textContent = sf.started ? `Progreso: ${sf.done}/${total} · activos=${sf.inFlight}${sf.paused?' · PAUSADO':''}` : 'En espera…';
    sfSetProgress(sf.done,total);
  }
  function famAllowedF(f){
    return f==='2'?tabElsF.chk.show2.checked:f==='3'?tabElsF.chk.show3.checked:f==='4'?tabElsF.chk.show4.checked:f==='5'?tabElsF.chk.show5.checked:true;
  }
  function sfRender(){
    const rows = sf.findings.filter(f=>f.session===sf.session && famAllowedF(f.family));
    const counts = { '2':0,'3':0,'4':0,'5':0,other:0 };
    rows.forEach(f=>{ if(counts[f.family]!==undefined) counts[f.family]++; else counts.other++; });
    tabElsF.c2.textContent = String(counts['2']||0);
    tabElsF.c3.textContent = String(counts['3']||0);
    tabElsF.c4.textContent = String(counts['4']||0);
    tabElsF.c5.textContent = String(counts['5']||0);
    tabElsF.cOther.textContent = String(counts.other||0);
    tabElsF.results.innerHTML='';
    if (filesTabBtn) filesTabBtn.textContent = `Files (${rows.length})`;
    rows.forEach(({url,status,note,family:fam})=>{
      const div = document.createElement('div'); div.className='ptk-row';
      div.innerHTML = `<div><a class="ptk-link" href="${url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${url}</a></div>
                       <div class="ptk-code" style="color:${famColor(fam)}">HTTP ${status}${note?` · ${note}`:''}</div>`;
      tabElsF.results.appendChild(div);
    });
  }
  [tabElsF.chk.show2,tabElsF.chk.show3,tabElsF.chk.show4,tabElsF.chk.show5].forEach(chk=>chk.addEventListener('change', sfRender));
  function sfBuildQueue(){
    const list = [];
    if (tabElsF.chk.useStatic.checked) list.push(...staticPaths);
    if (tabElsF.chk.useHost.checked) list.push(...makeArchiveVariants(seedsFromHost(), FILES.MAX_GEN));
    if (tabElsF.chk.usePath.checked) list.push(...makeArchiveVariants(seedsFromPath(), FILES.MAX_GEN));
    if (tabElsF.chk.prefixStatic.checked) list.push(...staticPaths.map(joinAtCurrent));
    if (tabElsF.chk.prefixInter.checked){
      const prefixes = getAllDirPrefixes().filter(p=>p!=='/');
      prefixes.forEach(pref => staticPaths.forEach(sp => list.push((pref + sp.replace(/^\/+/, '')).replace(/\/{2,}/g, '/'))));
    }
    if (tabElsF.chk.useDOM.checked) list.push(...collectDOMZips());
    if (tabElsF.chk.gql.checked) list.push(...buildGraphQLEndpoints());
    return unique(list.map(p=>mkAbs(p)).filter(Boolean).filter(sameOrigin));
  }
  function sfAddFinding(url,status,note,body=''){
    if (status===401 || status===403 || /<form[^>]*>([\s\S]*?<input[^>]*type=["']?password)/i.test(body)) {
      note += (note?'; ':'') + 'Requires auth';
    }
    const fam = family(status);
    sf.findings.push({ url, file:url, line:'', status, note, family: fam, session: sf.session });
    sfRender();
  }
  function sfPump(){
    if (sf.paused) return;
    while (sf.inFlight<FILES.MAX_CONCURRENCY && sf.idx<sf.queue.length){
      const u = sf.queue[sf.idx++]; const session = sf.session; sf.inFlight++; sfUpdateStatus();
      const isGQL = /\?query=/.test(u) || /\/(graphql|gql|graph|graphiql|playground|altair|voyager)(\b|\/|\?)/i.test(u);
      GM_xmlhttpRequest({
        method:'GET', url:u, timeout: FILES.TIMEOUT_MS,
        headers: isGQL ? {'Accept':'application/json'} : {'Range':'bytes=0-200','Cache-Control':'no-cache'},
        onload: res=>{
          if (session!==sf.session) return;
          let code = res.status; let note = '';
          const ctype = ((res.responseHeaders||'').match(/content-type:\s*([^\n\r]+)/i)||[])[1]?.trim()||'';
          if (code>=300 && code<400){
            const m = (res.responseHeaders||'').match(/location:\s*(.+)/i); note = m? m[1].trim() : '';
          } else if (code===200 || code===206){
            const body = (res.responseText||'').slice(0,400);
            if (looksLike404(body)) { code = 404; note='Soft 404'; }
            else if (isGQL){ if (/__typename|__schema|GraphQL|errors/i.test(body)) note='posible GraphQL activo'; }
            else if (/\b(AWS|secret|token|password|passwd|apikey|credential|private|jwt|DB_|DATABASE|OPENAPI|swagger|ssh|PRIVATE|BEGIN|env|dotenv|config|zip|tar|gzip|secret_key)\b/i.test(body)){ note='posible contenido sensible'; }
            if (/text\//i.test(ctype) && !/charset=/i.test(ctype)) note += (note?'; ':'') + 'sin charset';
          } else if (isGQL && code===400){ note='GraphQL detectado (400 típico)'; }
          else if (isGQL && code===405){ note='GraphQL podría requerir POST (405)'; }
          if (res.finalUrl && res.finalUrl !== u) note += (note?'; ':'') + `redirigido a ${res.finalUrl}`;
          sfAddFinding(u,code,note,res.responseText);
        },
        onerror: ()=>{ if (session!==sf.session) return; sfAddFinding(u,0,'Error de red'); },
        ontimeout: ()=>{ if (session!==sf.session) return; sfAddFinding(u,0,'Timeout'); },
        onloadend: ()=>{ if (session!==sf.session) return; sf.inFlight--; sf.done++; sfUpdateStatus(); setTimeout(sfPump, FILES.REQ_DELAY_MS); }
      });
    }
  }
  function sfStart(){
    if (sf.started) return;
    sf.started=true; sf.paused=false; sf.session++;
    sf.findings.length=0; tabElsF.results.innerHTML=''; sfRender();
    sf.queue = sfBuildQueue(); sf.idx=0; sf.inFlight=0; sf.done=0;
    if (!sf.queue.length){ tabElsF.status.textContent='Sin rutas para probar.'; sfSetProgress(0,0); sf.started=false; return; }
    sfUpdateStatus(); sfPump();
  }
  function sfPauseResume(){ if (!sf.started) return; sf.paused=!sf.paused; tabElsF.pause.textContent = sf.paused?'Reanudar':'Pausar'; sfUpdateStatus(); if (!sf.paused) sfPump(); }
  function sfClear(){ sf.paused=true; sf.started=false; sf.session++; sf.queue=[]; sf.inFlight=0; sf.idx=0; sf.done=0; sf.findings.length=0; tabElsF.results.innerHTML=''; tabElsF.status.textContent='En espera…'; sfSetProgress(0,0); tabElsF.pause.textContent='Pausar'; sfRender(); }
  tabElsF.start.onclick=sfStart; tabElsF.pause.onclick=sfPauseResume; tabElsF.clear.onclick=sfClear;
  tabElsF.copy.onclick=()=>{ const current=sf.findings.filter(f=>f.session===sf.session); const out=JSON.stringify(current,null,2); clip(out); tabElsF.copy.textContent='¡Copiado!'; setTimeout(()=>tabElsF.copy.textContent='Copiar JSON',1200); };
  tabElsF.csv.onclick=()=>{ const rows=sf.findings.filter(f=>f.session===sf.session); const head=['file','line','url','status','note','family']; csvDownload(`files_probe_${nowStr()}.csv`, head, rows); };

/* ============================
   JS Secret & Endpoint Hunter (dominios solo en strings/comentarios; scope; anti-ruido en minificados)
============================ */
const tabJS = panel.querySelector('#tab_discover_js');
const jsTabBtn = panel.querySelector('#tabs_discover .ptk-tab[data-tab="js"]');
tabJS.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">JS Secret & Endpoint Hunter</div>
      <div class="ptk-grid">
        <button id="js_start" class="ptk-btn">Escanear JS</button>
        <button id="js_pause" class="ptk-btn">Pausar JS</button>
        <button id="js_clear" class="ptk-btn">Clear JS</button>
        <button id="js_copy" class="ptk-btn">Copiar JSON</button>
        <button id="js_csv" class="ptk-btn">CSV</button>
      </div>
    </div>
    <div class="ptk-grid">
      <label><input type="checkbox" id="js_include_third"> Incluir externos</label>
      <label><input type="checkbox" id="js_scan_inline" checked> Incluir inline</label>
      <label><input type="checkbox" id="js_ignore_min" checked> Ignorar *.min.js</label>
      <label><input type="checkbox" id="js_capture_net"> Capturar fetch/XHR</label>
    </div>
    <div id="js_filters" class="ptk-grid"></div>
    <div class="ptk-grid">
      <label><input type="checkbox" id="js_domains" checked> Extraer dominios/subdominios</label>
      <label>Scope:
        <select id="js_scope">
          <option value="origin">Origen</option>
          <option value="base" selected>Dominio base</option>
          <option value="all">Todos</option>
        </select>
      </label>
      <label>Base override: <input type="text" id="js_base_override" placeholder="ej. ejemplo.com" style="width:160px"></label>
      <label><input type="checkbox" id="js_domains_strict" checked> Modo estricto dominios</label>
      <label><input type="checkbox" id="js_domains_ignore_min_ext" checked> No extraer dominios en *.min.js externos</label>
    </div>
    <div id="js_status" style="margin:6px 0">En espera…</div>
    <div id="js_results"></div>
  </div>
`;

// === PATTERNS (regex de hallazgos “secretos/URLs/rutas”) ===
const PATTERNS = [
  { key:'JWT',           label:'JWT',                         rx:/\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g },
  { key:'Bearer',        label:'Bearer',                      rx:/\bBearer\s+([A-Za-z0-9\-._~+/]+=*)/gi },
  { key:'GoogleAPI',     label:'Google API Key',              rx:/\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { key:'GitHubPAT',     label:'GitHub Token',                rx:/\bghp_[A-Za-z0-9]{36}\b/g },
  { key:'GitLabPAT',     label:'GitLab PAT',                  rx:/\bglpat-[A-Za-z0-9_\-]{20}\b/g },
  { key:'StripeSecret',  label:'Stripe Secret',               rx:/\bsk_(live|test)_[0-9A-Za-z]{24,}\b/g },
  { key:'StripePub',     label:'Stripe Publishable',          rx:/\bpk_(live|test)_[0-9A-Za-z]{24,}\b/g },
  { key:'AWSKey',        label:'AWS Access Key ID',           rx:/\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g },
  { key:'AuthHeader',    label:'Authorization header',        rx:/['"]Authorization['"]\s*:\s*['"]([^'"]+)['"]/gi },
  { key:'GenericSecret', label:'apiKey/token/secret var',     rx:/\b(api[_-]?key|token|secret|access[_-]?token)\b\s*[:=]\s*['"]([^'"]{8,})['"]/gi },
  { key:'Password',     label:'Password',                     rx:/password/i },
  { key:'Hex',          label:'Hex string',                   rx:/\b(?:[0-9a-f]{2}){4,}\b/gi },
  { key:'URL',           label:'Endpoint http(s)://',         rx:/https?:\/\/[a-z0-9.\-]+(?::\d+)?(?:\/[^\s'"<>()\]]*)?/gi },
  { key:'Route',         label:'Ruta /api|/v1|/auth|/graphql',rx:/(?:['"`])((?:\/|\.)?(?:api|v\d+|auth|graphql)[^'"`<>\s)]{0,160})(?:['"`])/gi }
];

// === Helpers para DOMINIOS solo desde strings/comentarios ===

// Lista blanca de TLDs comunes (puedes ampliar)
const COMMON_TLDS = new Set([
  'com','org','net','edu','gov','mil','int',
  'io','co','ai','app','dev','info','biz','xyz','me',
  'us','uk','mx','es','fr','de','it','nl','br','ar','ca','au','ch','jp','kr','cn','ru','in',
  'za','sg','hk','tw','tr','pl','se','no','fi','dk','pt','cz','sk','hu','ro','bg','gr','il',
  'cl','pe','uy','ve','gt','cr','pa','do','hn','ni','bo','py','ec'
]);

// Palabras JS comunes que NO queremos como labels de dominio
const JS_WORDS = new Set([
  'math','document','window','console','navigator','location','history','screen','element',
  'push','concat','length','apply','floor','ceil','round','max','min','map','filter','reduce',
  'every','some','find','includes','split','join','slice','splice','call','bind','prototype',
  'createrelement','queryselector','getelementbyid','type','src','href','class','style','value',
]);

function isValidHostnameSyntax(host){
  if (!host || typeof host!=='string') return false;
  host = host.trim().toLowerCase();
  if (host.length>253) return false;
  if (host.endsWith('.')) host = host.slice(0,-1);
  if (!host.includes('.')) return false;
  if (host.includes('_')) return false;
  const parts = host.split('.');
  for (const p of parts){
    if (!p.length || p.length>63) return false;
    if (!/^[a-z0-9-]+$/.test(p)) return false;
    if (p.startsWith('-') || p.endsWith('-')) return false;
  }
  return true;
}

function isLikelyBareDomain(host){
  if (!isValidHostnameSyntax(host)) return false;
  const parts = host.toLowerCase().split('.');
  const tld = parts[parts.length-1];
  const sld = parts[parts.length-2] || '';
  const left = parts[0];

  // TLD debe ser común (evita i.push, r.apply, Math.floor, etc.)
  if (!COMMON_TLDS.has(tld)) return false;

  // SLD mínimo 2 chars
  if (sld.length < 2) return false;

  // Evita tokens JS típicos
  if (JS_WORDS.has(tld) || JS_WORDS.has(sld) || JS_WORDS.has(left)) return false;

  return true;
}

// Extraer literales ' " ` (sin ${})
// (puedes moverla si ya la tienes)
function extractStringLiterals(line){
  const out = []; const rx = /(['"`])((?:\\.|(?!\1).)*)\1/g; let m;
  while ((m = rx.exec(line))){ out.push(m[2]); }
  return out;
}

// Buscar URLs/hosts dentro de una cadena (NO en código)
function findDomainsInString(str, pushHost){
  // 1) URLs con esquema: aceptar
  const urlRx = /https?:\/\/[^\s"'`<>()]+/gi;
  const urls = str.match(urlRx) || [];
  urls.forEach(u => { try { const h = new URL(u).hostname.toLowerCase(); if (isValidHostnameSyntax(h)) pushHost(h, u); } catch(e){ logError(e); } });

  // 2) protocol-relative //host/...
  const prx = /(^|[^a-z0-9])\/\/([a-z0-9.-]+)(?=\/|$)/gi;
  let m; while ((m = prx.exec(str))){ const h = m[2].toLowerCase(); if (isValidHostnameSyntax(h)) pushHost(h, '//'+h); }

  // 3) host “pelón”
  const bareRx = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi;
  let b; while((b = bareRx.exec(str))){
    const h = b[1].toLowerCase();
    const strictOn = !jsRefs.domStrict || jsRefs.domStrict.checked;
    if (strictOn ? isLikelyBareDomain(h) : isValidHostnameSyntax(h)) {
      pushHost(h, b[0]);
    }
  }
}

// === Refs y estado (esto es “los refs js”) ===
const jsRefs = {
  start: tabJS.querySelector('#js_start'),
  pause: tabJS.querySelector('#js_pause'),
  clear: tabJS.querySelector('#js_clear'),
  copy:  tabJS.querySelector('#js_copy'),
  csv:   tabJS.querySelector('#js_csv'),
  status:tabJS.querySelector('#js_status'),
  results:tabJS.querySelector('#js_results'),
  includeThird: tabJS.querySelector('#js_include_third'),
  scanInline:   tabJS.querySelector('#js_scan_inline'),
  ignoreMin:    tabJS.querySelector('#js_ignore_min'),
  captureNet:   tabJS.querySelector('#js_capture_net'),
  filterBox:    tabJS.querySelector('#js_filters'),
  domChk:       tabJS.querySelector('#js_domains'),
  scopeSel:     tabJS.querySelector('#js_scope'),
  baseOverride: tabJS.querySelector('#js_base_override'),
  domStrict:    tabJS.querySelector('#js_domains_strict'),
  domMinExt:    tabJS.querySelector('#js_domains_ignore_min_ext')
};
jsRefs.filterBox.innerHTML = PATTERNS.map(p=>`<label><input type="checkbox" data-key="${p.key}" checked> ${p.label}</label>`).join('');
const jsFilter = Object.fromEntries(PATTERNS.map(p=>[p.key,true]));
jsRefs.filterBox.querySelectorAll('input[type="checkbox"]').forEach(chk=>{
  chk.addEventListener('change', ()=>{ jsFilter[chk.dataset.key] = chk.checked; jsRender(); });
});

const pillJsTxt = pill.querySelector('#pill_js_txt');
const pillJsBar = pill.querySelector('#pill_js_bar');
const jh = { findings: [], domainsSet:new Set(), session: 0, targets: [], queueIdx: 0, active: 0, started: false, paused: false };

function jsSetProgress(done,total){
  const pct = total ? Math.round(done/total*100) : 0;
  pillJsTxt.textContent = total? `${done}/${total} • activos=${jh.active}${jh.paused?' • PAUSADO':''}` : '—';
  pillJsBar.style.width = pct + '%';
}
function jsUpdateStatus(){
  const total = jh.targets.length;
  jsRefs.status.textContent = jh.started ? `Progreso: ${jh.queueIdx}/${total} · activos=${jh.active}${jh.paused?' · PAUSADO':''}` : 'En espera…';
  jsSetProgress(jh.queueIdx, total);
}
function jsFilterKey(type){
  const pat = PATTERNS.find(p=>p.label===type || p.key===type);
  return pat ? jsFilter[pat.key] : true;
}
function jsRender(){
  const current = jh.findings.filter(f=>f.session===jh.session && (f.type==='Domain' || jsFilterKey(f.type)));
  jsRefs.results.innerHTML='';
  if (jsTabBtn) jsTabBtn.textContent = `JS Hunter (${current.length})`;
  current.forEach(f=>{
    const div = document.createElement('div'); div.className='ptk-row';
    div.innerHTML = `<div style="opacity:.8">${f.file}${typeof f.line==='number'?` :${f.line+1}`:''}</div>
                     <div><b>${f.type}</b>: <code class="ptk-code">${highlightEnc(escHTML(f.value))}</code>${f.host?` · <span style="opacity:.9">${f.host}</span>`:''}</div>`;
    jsRefs.results.appendChild(div);
  });
}
function addDomainFinding(file, line, host, evidence){
  const mode = jsRefs.scopeSel.value;
  const baseOv = (jsRefs.baseOverride.value||'').trim();
  if (!inScopeDomain(host, mode, baseOv)) return;
  const key = `${file}||${line||''}||${host}`;
  if (jh.domainsSet.has(key)) return;
  jh.domainsSet.add(key);
  jh.findings.push({ file, line, type:'Domain', value:evidence||host, host, session: jh.session });
}

function jsScanCaptured(file, text){
  const lines = (text || '').split(/\r?\n/);
  PATTERNS.forEach(p => {
    lines.forEach((ln,i)=>{
      const m = ln.match(p.rx);
      if (m) m.forEach(val=> jh.findings.push({ file, type:p.label, value:val, line:i, session: jh.session }));
    });
  });
  if (jsRefs.domChk.checked){
    lines.forEach((ln,i)=>{
      findDomainsInString(ln,(host,e)=>addDomainFinding(file,i,host,e));
    });
  }
}
function jsProcessCapture(src, headers, body){
  if (headers) jsScanCaptured(src+' [hdr]', headers);
  if (body) jsScanCaptured(src+' [body]', body);
  jsRender();
}
const _origFetch = window.fetch;
window.fetch = async function(...args){
  const res = await _origFetch.apply(this,args);
  if (jsRefs.captureNet && jsRefs.captureNet.checked){
    try {
      const url = typeof args[0]==='string'? args[0] : (args[0] && args[0].url) || '';
      if(liveNet) logEvent('network', { method:'fetch', url });
      const clone = res.clone();
      const hdrs = Array.from(clone.headers.entries()).map(([k,v])=>`${k}: ${v}`).join('\n');
      withTimeout(clone.text(), JS.TIMEOUT_MS)
        .then(body=>jsProcessCapture('fetch '+url,hdrs,body))
        .catch(e=>logError(e));
    } catch(e){ logError(e); }
  }
  return res;
};
const _origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(...args){
  this.addEventListener('load', function(){
    if (jsRefs.captureNet && jsRefs.captureNet.checked){
      try {
        const hdrs = this.getAllResponseHeaders();
        const body = this.responseText || '';
        const url = this.responseURL || '';
        if(liveNet) logEvent('network', { method:'xhr', url });
        jsProcessCapture('xhr '+url,hdrs,body);
      } catch(e){ logError(e); }
    }
  });
  return _origSend.apply(this,args);
};

// === jsScanText (dominios solo en strings/comentarios + anti-ruido en minificados externos) ===
function jsScanText(file, text) {
  const lines = (text || '').split(/\r?\n/);

  // 0) ¿Saltamos DOMINIOS en *.min.js externos?
  const skipDomainsHere = (
    jsRefs.domMinExt && jsRefs.domMinExt.checked &&
    !sameOrigin(file) &&
    /\.min\.js(\?|#|$)/i.test(file)
  );

  // 1) Patrones de secretos/URLs/rutas
  PATTERNS.forEach(p => {
    lines.forEach((ln, i) => {
      const m = ln.match(p.rx);
      if (m) m.forEach(val => jh.findings.push({ file, type: p.label, value: val, line: i, session: jh.session }));
    });
  });

  // 2) DOMINIOS — solo strings y comentarios
  if (!skipDomainsHere && jsRefs.domChk.checked){
    lines.forEach((ln, i) => {
      // a) strings
      const strLits = extractStringLiterals(ln);
      strLits.forEach(s => {
        findDomainsInString(s, (host, evidence) => addDomainFinding(file, i, host, evidence));
      });
      // b) comentario //... (quitando strings para no confundir “//” dentro de ellas)
      const noStr = ln.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
      const idx = noStr.indexOf('//');
      if (idx >= 0) {
        const comment = noStr.slice(idx + 2);
        findDomainsInString(comment, (host, evidence) => addDomainFinding(file, i, host, evidence));
      }
    });
  }

  jsRender();
}

function jsCollectTargets(){
  const scripts = [...document.scripts];
  const targets = [];
  scripts.forEach(s=>{
    const src = s.src || '';
    if (!src){
      if (jsRefs.scanInline.checked) targets.push({ file:'(inline)', inline:true, node:s });
    } else {
      if (jsRefs.ignoreMin.checked && /\.min\.js(\?|#|$)/i.test(src)) return;
      const isSame = sameOrigin(src);
      if (isSame || jsRefs.includeThird.checked) targets.push({ file:src, inline:false });
    }
  });
  return targets;
}
function jsPump(){
  if (jh.paused) return;
  while (jh.active<JS.MAX_CONCURRENCY && jh.queueIdx<jh.targets.length){
    const tgt = jh.targets[jh.queueIdx++];
    const session = jh.session;
    jh.active++;
    jsUpdateStatus();

    const finalize = (()=>{
      let done = false;
      return () => {
        if (done) return;
        done = true;
        if (session===jh.session){
          jh.active--;
          jsUpdateStatus();
          setTimeout(jsPump, JS.FETCH_DELAY_MS);
        }
      };
    })();

    if (tgt.inline){
      try { jsScanText(tgt.file, tgt.node.textContent || ''); } catch(e){ logError(e); }
      finalize();
      continue;
    }

    GM_xmlhttpRequest({
      method:'GET',
      url:tgt.file,
      timeout: JS.TIMEOUT_MS,
      onload: res => { if (session===jh.session) jsScanText(tgt.file, res.responseText || ''); },
      onerror: finalize,
      ontimeout: finalize,
      onloadend: finalize
    });
  }
}
function jsStart(){
  if (jh.started) return;
  jh.started=true; jh.paused=false; jh.session++; jh.domainsSet.clear();
  jh.findings.length=0; jsRefs.results.innerHTML=''; jsRender();
  jh.targets = jsCollectTargets(); jh.queueIdx=0; jh.active=0;
  if (!jh.targets.length){ jsRefs.status.textContent='Sin scripts para analizar.'; jsSetProgress(0,0); jh.started=false; return; }
  jsUpdateStatus(); jsPump();
}
function jsPauseResume(){ if (!jh.started) return; jh.paused=!jh.paused; jsRefs.pause.textContent=jh.paused?'Reanudar JS':'Pausar JS'; jsUpdateStatus(); if (!jh.paused) jsPump(); }
function jsClear(){ jh.paused=true; jh.started=false; jh.session++; jh.targets=[]; jh.queueIdx=0; jh.active=0; jh.findings.length=0; jh.domainsSet.clear(); jsRefs.results.innerHTML=''; jsRefs.status.textContent='En espera…'; jsSetProgress(0,0); jsRefs.pause.textContent='Pausar JS'; jsRender(); }

jsRefs.start.onclick=jsStart; jsRefs.pause.onclick=jsPauseResume; jsRefs.clear.onclick=jsClear;
jsRefs.copy.onclick=()=>{ const current=jh.findings.filter(f=>f.session===jh.session); const out=JSON.stringify(current,null,2); clip(out); jsRefs.copy.textContent='¡Copiado!'; setTimeout(()=>jsRefs.copy.textContent='Copiar JSON',1200); };
jsRefs.csv.onclick=()=>{ const rows=jh.findings.filter(f=>f.session===jh.session).map(r=>({file:r.file,line: (typeof r.line==='number'?(r.line+1):''),type:r.type,value:r.value,host:r.host||''})); const head=['file','line','type','value','host']; csvDownload(`js_hunter_${nowStr()}.csv`, head, rows); };

/* ============================
   Runtime Network
============================ */
const tabRuntime = panel.querySelector('#tab_runtime_network');
tabRuntime.innerHTML = `
  <div class="ptk-tabs" id="tabs_runtime_network_inner">
    <div class="ptk-tab active" data-tab="secrets">Secrets</div>
    <div class="ptk-tab" data-tab="network">Network</div>
  </div>
  <section id="tab_runtime_network_secrets"></section>
  <section id="tab_runtime_network_network" style="display:none"></section>
`;
initTabs('runtime_network', ['secrets','network'], tabRuntime);

const tabSecrets = tabRuntime.querySelector('#tab_runtime_network_secrets');
tabSecrets.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Runtime Secrets</div>
      <div class="ptk-grid">
        <button id="rs_clear" class="ptk-btn">Clear</button>
        <button id="rs_copy" class="ptk-btn">Copiar JSON</button>
        <button id="rs_dl" class="ptk-btn">Descargar TXT</button>
        <button id="rs_pm_toggle" class="ptk-btn">Pausar postMessage</button>
      </div>
    </div>
    <div id="rs_results"></div>
  </div>
`;
const rsRefs = {
  clear: tabSecrets.querySelector('#rs_clear'),
  copy:  tabSecrets.querySelector('#rs_copy'),
  dl:    tabSecrets.querySelector('#rs_dl'),
  pmToggle: tabSecrets.querySelector('#rs_pm_toggle'),
  results: tabSecrets.querySelector('#rs_results')
};
rsRefs.pmToggle.textContent = capturePostMessage ? 'Pausar postMessage' : 'Reanudar postMessage';
rsRender = function(){
  rsRefs.results.innerHTML='';
  runtimeLogs.forEach((r,i)=>{
    const div=document.createElement('div'); div.className='ptk-row';
    const top=document.createElement('div'); top.style.opacity='.8'; top.textContent=`${i+1} • ${r.type}`;
    const code=document.createElement('code'); code.className='ptk-code'; code.style.whiteSpace='pre-wrap';
    let txt;
    if (r.code !== undefined){
      txt = r.code;
    } else {
      const parts = [];
      if (r.key !== undefined) parts.push(`key: ${r.key}`);
      if (r.iv !== undefined) parts.push(`iv: ${r.iv}`);
      if (r.data !== undefined) parts.push(`data: ${r.data}`);
      txt = parts.join('\n');
    }
    code.innerHTML = highlightEnc(escHTML(txt));
    div.appendChild(top); div.appendChild(code); rsRefs.results.appendChild(div);
  });
};
rsRender();
rsRefs.clear.onclick=()=>{ runtimeLogs.length=0; rsRender(); updateRuntimeBadge(); };
rsRefs.copy.onclick=()=>{ const out=JSON.stringify(runtimeLogs,null,2); clip(out); rsRefs.copy.textContent='¡Copiado!'; setTimeout(()=>rsRefs.copy.textContent='Copiar JSON',1200); };
rsRefs.dl.onclick=()=>{
  const data = { logs: runtimeLogs, globals: getAllGlobals() };
  const out = JSON.stringify(data, null, 2);
  textDownload(`runtime_secrets_${nowStr()}.txt`, out);
};
rsRefs.pmToggle.onclick=()=>{
  capturePostMessage = !capturePostMessage;
  rsRefs.pmToggle.textContent = capturePostMessage ? 'Pausar postMessage' : 'Reanudar postMessage';
};

const tabNet = tabRuntime.querySelector('#tab_runtime_network_network');
tabNet.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Network</div>
      <div class="ptk-grid">
        <input id="net_txt" class="ptk-input" placeholder="Texto" style="width:80px">
        <input id="net_host" class="ptk-input" placeholder="Host" style="width:80px">
        <input id="net_method" class="ptk-input" placeholder="Método/tipo" style="width:100px">
        <input id="net_status" class="ptk-input" placeholder="Status" style="width:60px">
        <button id="net_pause" class="ptk-btn">Pausar</button>
        <button id="net_clear" class="ptk-btn">Clear</button>
        <button id="net_json" class="ptk-btn">JSON</button>
        <button id="net_csv" class="ptk-btn">CSV</button>
        <button id="net_md" class="ptk-btn">Pinned MD</button>
        <span id="net_sampling" style="color:#f87171;display:none">sampling ON</span>
      </div>
    </div>
    <div style="max-height:200px;overflow:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>ts</th><th>tipo</th><th>método/evt</th><th>url</th><th>status</th><th>ms</th><th>size</th><th>acciones</th></tr></thead>
        <tbody id="net_rows"></tbody>
      </table>
    </div>
  </div>
  <div id="net_det" class="ptk-box" style="display:none"></div>
`;
const netRefs={
  txt:tabNet.querySelector('#net_txt'),
  host:tabNet.querySelector('#net_host'),
  method:tabNet.querySelector('#net_method'),
  status:tabNet.querySelector('#net_status'),
  pause:tabNet.querySelector('#net_pause'),
  clear:tabNet.querySelector('#net_clear'),
  json:tabNet.querySelector('#net_json'),
  csv:tabNet.querySelector('#net_csv'),
  md:tabNet.querySelector('#net_md'),
  sampling:tabNet.querySelector('#net_sampling'),
  rows:tabNet.querySelector('#net_rows'),
  details:tabNet.querySelector('#net_det')
};
function highlightUrl(u){
  try{ const x=new URL(u, location.href); const h=escHTML(x.host); return escHTML(u).replace(h, `<span style="color:#93c5fd">${h}</span>`); }catch(_e){ return escHTML(u); }
}
function netFiltered(){
  const t=netRefs.txt.value.toLowerCase();
  const h=netRefs.host.value.toLowerCase();
  const m=netRefs.method.value.toLowerCase();
  const s=netRefs.status.value.trim();
  return netLogs.filter(r=>{
    if(t && !r.url.toLowerCase().includes(t)) return false;
    if(h && !(r.host||'').toLowerCase().includes(h)) return false;
    if(m && !((r.method||'').toLowerCase().includes(m) || r.type.toLowerCase().includes(m))) return false;
    if(s){ const parts=s.split('-'); const st=Number(r.status||0); if(parts[0] && st<Number(parts[0])) return false; if(parts[1] && st>Number(parts[1])) return false; }
    return true;
  });
}
netRender = function(){
  const list=netFiltered();
  renderChunked(list, netRefs.rows, rec=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(rec.ts).toLocaleTimeString()}</td><td>${escHTML(rec.type)}</td><td>${escHTML(rec.method||'')}</td><td>${highlightUrl(rec.url)}</td><td>${rec.status||''}</td><td>${rec.ms||''}</td><td>${rec.size||''}</td><td></td>`;
    const actions=tr.lastElementChild;
    const copy=document.createElement('button'); copy.className='ptk-btn'; copy.textContent='Copy';
    copy.onclick=()=>{ clip(JSON.stringify(rec,null,2)); copy.textContent='¡Copiado!'; setTimeout(()=>copy.textContent='Copy',1200); };
    const det=document.createElement('button'); det.className='ptk-btn'; det.textContent='Details';
    det.onclick=()=>{ let html=`<div class="ptk-flex"><div class="ptk-hdr">${escHTML(rec.method||rec.type)} ${escHTML(rec.url)}</div><button id="net_det_close" class="ptk-btn">Cerrar</button></div>`; if(rec.reqHeaders){ html+=`<div><b>Request Headers</b><pre class="ptk-code">${escHTML(Object.entries(rec.reqHeaders).map(([k,v])=>k+': '+v).join('\n'))}</pre></div>`; } if(rec.reqBody){ html+=`<div><b>Request Body</b><pre class="ptk-code">${escHTML(rec.reqBody)}</pre></div>`; } if(rec.resHeaders){ html+=`<div><b>Response Headers</b><pre class="ptk-code">${escHTML(Object.entries(rec.resHeaders).map(([k,v])=>k+': '+v).join('\n'))}</pre></div>`; } if(rec.resBody){ html+=`<div><b>Response Body</b><pre class="ptk-code">${escHTML(rec.resBody)}</pre></div>`; } netRefs.details.innerHTML=html; netRefs.details.style.display=''; netRefs.details.querySelector('#net_det_close').onclick=()=>{ netRefs.details.style.display='none'; }; };
    const pin=document.createElement('button'); pin.className='ptk-btn'; pin.textContent=isPinned(netPins,rec)?'Unpin':'Pin';
    pin.onclick=()=>togglePin(netPins,rec,pin,'net');
    actions.appendChild(copy); actions.appendChild(det); actions.appendChild(pin);
    return tr;
  }, '<tr><td colspan="8">Sin datos</td></tr>');
};
netRefs.txt.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_net_txt`, netRefs.txt.value); }catch(_e){}; netRender(); };
netRefs.host.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_net_host`, netRefs.host.value); }catch(_e){}; netRender(); };
netRefs.method.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_net_method`, netRefs.method.value); }catch(_e){}; netRender(); };
netRefs.status.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_net_status`, netRefs.status.value); }catch(_e){}; netRender(); };
netRefs.clear.onclick=()=>{ netLogs.length=0; netRender(); updateRuntimeBadge(); };
netRefs.pause.onclick=()=>{ netPaused=!netPaused; netRefs.pause.textContent=netPaused?'Reanudar':'Pausar'; try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_net_paused`, netPaused); }catch(_e){}; };
netRefs.json.onclick=()=>{ const out=JSON.stringify(netFiltered(),null,2); clip(out); netRefs.json.textContent='¡Copiado!'; setTimeout(()=>netRefs.json.textContent='JSON',1200); };
netRefs.csv.onclick=()=>{ const head=['ts','type','method','url','status','ms','size']; const rows=netFiltered().map(r=>({ts:new Date(r.ts).toISOString(),type:r.type,method:r.method,url:r.url,status:r.status,ms:r.ms,size:r.size})); csvDownload(`network_${nowStr()}.csv`, head, rows); };
netRefs.md.onclick=()=>{ const cols=['ts','type','method','url','status','ms','size']; const rows=netPins.map(r=>({ts:new Date(r.ts).toISOString(),type:r.type,method:r.method,url:r.url,status:r.status,ms:r.ms,size:r.size})); clip(rowsToMarkdown(rows,cols)); netRefs.md.textContent='¡Copiado!'; setTimeout(()=>netRefs.md.textContent='Pinned MD',1200); };
try{ if(typeof GM_getValue==='function'){ netRefs.txt.value=GM_getValue(`${site}_net_txt`, ''); netRefs.host.value=GM_getValue(`${site}_net_host`, ''); netRefs.method.value=GM_getValue(`${site}_net_method`, ''); netRefs.status.value=GM_getValue(`${site}_net_status`, ''); netPaused=GM_getValue(`${site}_net_paused`, false); netRefs.pause.textContent=netPaused?'Reanudar':'Pausar'; } }catch(_e){}
netRender();
function netSamplingLoop(){ netRefs.sampling.style.display = (globalThis.TREventBus && globalThis.TREventBus.sampling)?'':'none'; requestAnimationFrame(netSamplingLoop); }
netSamplingLoop();

const tabMessaging = panel.querySelector('#tab_runtime_messaging');
const msgRefs = {
  txt: tabMessaging.querySelector('#msg_txt'),
  channel: tabMessaging.querySelector('#msg_channel'),
  origin: tabMessaging.querySelector('#msg_origin'),
  target: tabMessaging.querySelector('#msg_target'),
  pause: tabMessaging.querySelector('#msg_pause'),
  clear: tabMessaging.querySelector('#msg_clear'),
  json: tabMessaging.querySelector('#msg_json'),
  csv: tabMessaging.querySelector('#msg_csv'),
  md: tabMessaging.querySelector('#msg_md'),
  rows: tabMessaging.querySelector('#msg_rows')
};
function msgFiltered(){
  const t=msgRefs.txt.value.toLowerCase();
  const c=msgRefs.channel.value.toLowerCase();
  const o=msgRefs.origin.value.toLowerCase();
  const g=msgRefs.target.value.toLowerCase();
  return msgLogs.filter(r=>{
    if(t && !(r.preview||'').toLowerCase().includes(t)) return false;
    if(c && !(r.channel||'').toLowerCase().includes(c)) return false;
    if(o && !(r.origin||'').toLowerCase().includes(o)) return false;
    if(g && !(r.target||'').toLowerCase().includes(g)) return false;
    return true;
  });
}
msgRender = function(){
  const list=msgFiltered();
  renderChunked(list, msgRefs.rows, rec=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(rec.ts).toLocaleTimeString()}</td><td>${escHTML(rec.channel+'/'+rec.type)}</td><td>${escHTML(rec.origin)}</td><td>${escHTML(rec.target)}</td><td>${rec.size}</td><td>${escHTML(rec.preview)}</td><td></td>`;
    const actions=tr.lastElementChild;
    const pin=document.createElement('button'); pin.className='ptk-btn'; pin.textContent=isPinned(msgPins,rec)?'Unpin':'Pin';
    pin.onclick=()=>togglePin(msgPins,rec,pin,'msg');
    actions.appendChild(pin);
    return tr;
  }, '<tr><td colspan="7">Sin datos</td></tr>');
};
msgRefs.txt.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_msg_txt`, msgRefs.txt.value); }catch(_e){}; msgRender(); };
msgRefs.channel.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_msg_channel`, msgRefs.channel.value); }catch(_e){}; msgRender(); };
msgRefs.origin.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_msg_origin`, msgRefs.origin.value); }catch(_e){}; msgRender(); };
msgRefs.target.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_msg_target`, msgRefs.target.value); }catch(_e){}; msgRender(); };
msgRefs.clear.onclick=()=>{ msgLogs.length=0; msgRender(); updateRuntimeBadge(); };
msgRefs.pause.onclick=()=>{ msgPaused=!msgPaused; msgRefs.pause.textContent=msgPaused?'Reanudar':'Pausar'; try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_msg_paused`, msgPaused); }catch(_e){}; };
msgRefs.json.onclick=()=>{ const out=JSON.stringify(msgFiltered(),null,2); clip(out); msgRefs.json.textContent='¡Copiado!'; setTimeout(()=>msgRefs.json.textContent='JSON',1200); };
msgRefs.csv.onclick=()=>{ const head=['ts','channel','type','origin','target','size','preview']; const rows=msgFiltered().map(r=>({ts:new Date(r.ts).toISOString(),channel:r.channel,type:r.type,origin:r.origin,target:r.target,size:r.size,preview:r.preview})); csvDownload(`messaging_${nowStr()}.csv`, head, rows); };
msgRefs.md.onclick=()=>{ const cols=['ts','channel','type','origin','target','size','preview']; const rows=msgPins.map(r=>({ts:new Date(r.ts).toISOString(),channel:r.channel,type:r.type,origin:r.origin,target:r.target,size:r.size,preview:r.preview})); clip(rowsToMarkdown(rows,cols)); msgRefs.md.textContent='¡Copiado!'; setTimeout(()=>msgRefs.md.textContent='Pinned MD',1200); };
try{ if(typeof GM_getValue==='function'){ msgRefs.txt.value=GM_getValue(`${site}_msg_txt`, ''); msgRefs.channel.value=GM_getValue(`${site}_msg_channel`, ''); msgRefs.origin.value=GM_getValue(`${site}_msg_origin`, ''); msgRefs.target.value=GM_getValue(`${site}_msg_target`, ''); msgPaused=GM_getValue(`${site}_msg_paused`, false); msgRefs.pause.textContent=msgPaused?'Reanudar':'Pausar'; } }catch(_e){}
msgRender();
updateRuntimeBadge();

/* ============================
   Runtime Codecs
============================ */
const tabCodecs = panel.querySelector('#tab_runtime_codecs');
tabCodecs.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Codecs</div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="cd_btoa"> btoa</label>
        <label><input type="checkbox" id="cd_text"> TextEncoder/Decoder</label>
        <button id="cd_clear" class="ptk-btn">Clear</button>
        <button id="cd_json" class="ptk-btn">JSON</button>
        <button id="cd_csv" class="ptk-btn">CSV</button>
        <button id="cd_md" class="ptk-btn">Pinned MD</button>
      </div>
    </div>
    <div style="max-height:200px;overflow:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>ts</th><th>codec</th><th>len</th><th>JSON</th><th>JWT</th><th>input</th><th>output</th><th>acciones</th></tr></thead>
        <tbody id="cd_rows"></tbody>
      </table>
    </div>
  </div>
`;
const cdRefs = {
  btoa: tabCodecs.querySelector('#cd_btoa'),
  text: tabCodecs.querySelector('#cd_text'),
  clear: tabCodecs.querySelector('#cd_clear'),
  json: tabCodecs.querySelector('#cd_json'),
  csv: tabCodecs.querySelector('#cd_csv'),
  md: tabCodecs.querySelector('#cd_md'),
  rows: tabCodecs.querySelector('#cd_rows')
};
cdRefs.btoa.checked = codecCfg.btoa;
cdRefs.text.checked = codecCfg.text;
cdRefs.btoa.onchange=()=>{ codecCfg.btoa=cdRefs.btoa.checked; try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_codec_btoa`, codecCfg.btoa); }catch(_e){}; };
cdRefs.text.onchange=()=>{ codecCfg.text=cdRefs.text.checked; try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_codec_text`, codecCfg.text); }catch(_e){}; };
codecRender = function(){
  renderChunked(codecLogs, cdRefs.rows, rec=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(rec.ts).toLocaleTimeString()}</td><td>${escHTML(rec.codec)}</td><td>${rec.length}</td><td>${rec.isJSON}</td><td>${rec.isJWT}</td><td>${escHTML(rec.inputPreview)}</td><td>${escHTML(rec.outputPreview)}</td><td></td>`;
    const actions=tr.lastElementChild;
    const inBtn=document.createElement('button'); inBtn.className='ptk-btn'; inBtn.textContent='In';
    inBtn.onclick=()=>{ clip(rec.inputFull); inBtn.textContent='¡Copiado!'; setTimeout(()=>inBtn.textContent='In',1200); };
    const outBtn=document.createElement('button'); outBtn.className='ptk-btn'; outBtn.textContent='Out';
    outBtn.onclick=()=>{ clip(rec.outputFull); outBtn.textContent='¡Copiado!'; setTimeout(()=>outBtn.textContent='Out',1200); };
    const pin=document.createElement('button'); pin.className='ptk-btn'; pin.textContent=isPinned(cdPins,rec)?'Unpin':'Pin';
    pin.onclick=()=>togglePin(cdPins,rec,pin,'codec');
    actions.appendChild(inBtn); actions.appendChild(outBtn); actions.appendChild(pin);
    return tr;
  }, '<tr><td colspan="8">Sin datos</td></tr>');
};
cdRefs.clear.onclick=()=>{ codecLogs.length=0; codecRender(); updateRuntimeBadge(); };
cdRefs.json.onclick=()=>{ const out=JSON.stringify(codecLogs,null,2); clip(out); cdRefs.json.textContent='¡Copiado!'; setTimeout(()=>cdRefs.json.textContent='JSON',1200); };
cdRefs.csv.onclick=()=>{ const head=['ts','codec','length','isJSON','isJWT','input','output']; const rows=codecLogs.map(r=>({ts:new Date(r.ts).toISOString(),codec:r.codec,length:r.length,isJSON:r.isJSON,isJWT:r.isJWT,input:r.inputFull,output:r.outputFull})); csvDownload(`codecs_${nowStr()}.csv`, head, rows); };
cdRefs.md.onclick=()=>{ const cols=['ts','codec','length','isJSON','isJWT','input','output']; const rows=cdPins.map(r=>({ts:new Date(r.ts).toISOString(),codec:r.codec,length:r.length,isJSON:r.isJSON,isJWT:r.isJWT,input:r.inputFull,output:r.outputFull})); clip(rowsToMarkdown(rows,cols)); cdRefs.md.textContent='¡Copiado!'; setTimeout(()=>cdRefs.md.textContent='Pinned MD',1200); };
codecRender();
updateRuntimeBadge();

/* ============================
  Runtime Console & Errors
============================ */
const tabCE = panel.querySelector('#tab_runtime_console');
tabCE.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Console & Errors</div>
      <div class="ptk-grid">
        <select id="ce_level" class="ptk-input">
          <option value="">nivel</option>
          <option value="log">log</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
        <input id="ce_txt" class="ptk-input" placeholder="Texto" style="width:100px">
        <button id="ce_clear" class="ptk-btn">Clear</button>
        <button id="ce_json" class="ptk-btn">JSON</button>
        <button id="ce_csv" class="ptk-btn">CSV</button>
        <button id="ce_md" class="ptk-btn">Pinned MD</button>
      </div>
    </div>
    <div style="max-height:200px;overflow:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>ts</th><th>nivel</th><th>mensaje</th><th>source</th><th>stack</th><th>acciones</th></tr></thead>
        <tbody id="ce_rows"></tbody>
      </table>
    </div>
  </div>
`;
const ceRefs = {
  level: tabCE.querySelector('#ce_level'),
  txt: tabCE.querySelector('#ce_txt'),
  clear: tabCE.querySelector('#ce_clear'),
  json: tabCE.querySelector('#ce_json'),
  csv: tabCE.querySelector('#ce_csv'),
  md: tabCE.querySelector('#ce_md'),
  rows: tabCE.querySelector('#ce_rows')
};
function ceFiltered(){
  const lvl = ceRefs.level.value;
  const txt = ceRefs.txt.value.toLowerCase();
  return consoleLogs.filter(r=>{
    if(lvl && r.level!==lvl) return false;
    if(txt && !(r.message||'').toLowerCase().includes(txt)) return false;
    return true;
  });
}
renderCE = function(){
  const list = ceFiltered();
  renderChunked(list, ceRefs.rows, rec=>{
    const src = rec.source ? `${rec.source}:${rec.line||''}:${rec.col||''}` : '';
    const stack = rec.stack ? `<details><summary>ver</summary><pre class="ptk-code">${escHTML(rec.stack)}</pre></details>` : '';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(rec.ts).toLocaleTimeString()}</td><td>${escHTML(rec.level)}</td><td>${escHTML(rec.message)}</td><td>${escHTML(src)}</td><td>${stack}</td><td></td>`;
    const actions=tr.lastElementChild;
    const copy=document.createElement('button'); copy.className='ptk-btn'; copy.textContent='Copy';
    copy.onclick=()=>{ clip(JSON.stringify(rec,null,2)); copy.textContent='¡Copiado!'; setTimeout(()=>copy.textContent='Copy',1200); };
    const pin=document.createElement('button'); pin.className='ptk-btn'; pin.textContent=isPinned(cePins,rec)?'Unpin':'Pin';
    pin.onclick=()=>togglePin(cePins,rec,pin,'console');
    actions.appendChild(copy); actions.appendChild(pin);
    return tr;
  }, '<tr><td colspan="6">Sin datos</td></tr>');
  updateRuntimeBadge();
};
ceRefs.level.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_ce_level`, ceRefs.level.value); }catch(_e){}; renderCE(); };
ceRefs.txt.oninput=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_ce_txt`, ceRefs.txt.value); }catch(_e){}; renderCE(); };
ceRefs.clear.onclick=()=>{ consoleLogs.length=0; consoleLogKeys.clear(); renderCE(); renderConsole(); };
ceRefs.json.onclick=()=>{ const out=JSON.stringify(ceFiltered(),null,2); clip(out); ceRefs.json.textContent='¡Copiado!'; setTimeout(()=>ceRefs.json.textContent='JSON',1200); };
ceRefs.csv.onclick=()=>{ const head=['ts','level','message','source','line','col','stack']; const rows=ceFiltered().map(r=>({ts:new Date(r.ts).toISOString(),level:r.level,message:r.message,source:r.source||'',line:r.line||'',col:r.col||'',stack:r.stack||''})); csvDownload(`console_${nowStr()}.csv`, head, rows); };
ceRefs.md.onclick=()=>{ const cols=['ts','level','message','source','stack']; const rows=cePins.map(r=>({ts:new Date(r.ts).toISOString(),level:r.level,message:r.message,source:r.source||'',stack:r.stack||''})); clip(rowsToMarkdown(rows,cols)); ceRefs.md.textContent='¡Copiado!'; setTimeout(()=>ceRefs.md.textContent='Pinned MD',1200); };
try{ if(typeof GM_getValue==='function'){ ceRefs.level.value=GM_getValue(`${site}_ce_level`, ''); ceRefs.txt.value=GM_getValue(`${site}_ce_txt`, ''); } }catch(_e){}
renderCE();

/* ============================
  Runtime Crypto
============================ */
const tabCrypto = panel.querySelector('#tab_runtime_crypto');
tabCrypto.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Crypto</div>
      <div class="ptk-grid">
        <button id="cr_clear" class="ptk-btn">Clear</button>
        <button id="cr_json" class="ptk-btn">JSON</button>
        <button id="cr_csv" class="ptk-btn">CSV</button>
        <button id="cr_md" class="ptk-btn">Pinned MD</button>
      </div>
    </div>
    <div style="max-height:200px;overflow:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th>ts</th><th>tipo</th><th>alg</th><th>key</th><th>iv</th><th>len</th><th>sample</th><th>acciones</th></tr></thead>
        <tbody id="cr_rows"></tbody>
      </table>
    </div>
  </div>
`;
const cyRefs = {
  clear: tabCrypto.querySelector('#cr_clear'),
  json: tabCrypto.querySelector('#cr_json'),
  csv: tabCrypto.querySelector('#cr_csv'),
  md: tabCrypto.querySelector('#cr_md'),
  rows: tabCrypto.querySelector('#cr_rows')
};
cryptoRender = function(){
  renderChunked(cryptoLogs, cyRefs.rows, rec=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${new Date(rec.ts).toLocaleTimeString()}</td><td>${escHTML(rec.type)}</td><td>${escHTML(rec.alg)}</td><td>${escHTML(rec.keyPreview||'')}</td><td>${escHTML(rec.ivPreview||'')}</td><td>${rec.length||''}</td><td>${escHTML(rec.sample||'')}</td><td></td>`;
    const actions=tr.lastElementChild;
    const pin=document.createElement('button'); pin.className='ptk-btn'; pin.textContent=isPinned(cryptoPins,rec)?'Unpin':'Pin';
    pin.onclick=()=>togglePin(cryptoPins,rec,pin,'crypto');
    actions.appendChild(pin);
    return tr;
  }, '<tr><td colspan="8">Sin datos</td></tr>');
};
cyRefs.clear.onclick=()=>{ cryptoLogs.length=0; cryptoRender(); updateRuntimeBadge(); };
cyRefs.json.onclick=()=>{ const out=JSON.stringify(cryptoLogs,null,2); clip(out); cyRefs.json.textContent='¡Copiado!'; setTimeout(()=>cyRefs.json.textContent='JSON',1200); };
cyRefs.csv.onclick=()=>{ const head=['ts','type','alg','keyPreview','ivPreview','length','sample']; const rows=cryptoLogs.map(r=>({ts:new Date(r.ts).toISOString(),type:r.type,alg:r.alg,keyPreview:r.keyPreview,ivPreview:r.ivPreview,length:r.length,sample:r.sample})); csvDownload(`crypto_${nowStr()}.csv`, head, rows); };
cyRefs.md.onclick=()=>{ const cols=['ts','type','alg','keyPreview','ivPreview','length','sample']; const rows=cryptoPins.map(r=>({ts:new Date(r.ts).toISOString(),type:r.type,alg:r.alg,keyPreview:r.keyPreview,ivPreview:r.ivPreview,length:r.length,sample:r.sample})); clip(rowsToMarkdown(rows,cols)); cyRefs.md.textContent='¡Copiado!'; setTimeout(()=>cyRefs.md.textContent='Pinned MD',1200); };
cryptoRender();
updateRuntimeBadge();

{ // Global variables/functions viewer
  try {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    const base = new Set(Object.getOwnPropertyNames(iframe.contentWindow));
    document.body.removeChild(iframe);
    ['scanChunksAndTs','createGlobalViewer'].forEach(n => base.add(n));
    const gv = createGlobalViewer(window, base);
    if (gv) {
      tabRuntime.appendChild(gv.container);
      tabRuntime.appendChild(gv.output);
    }
  } catch(e){ logError(e); }
}

  // Hook CryptoJS AES encrypt/decrypt
  (function(){
    try{
      const aes = window.CryptoJS && window.CryptoJS.AES;
      if(!aes) return;
      const wrap = fnName=>{
        if(typeof aes[fnName] !== 'function') return;
        const orig = aes[fnName];
        aes[fnName] = function(data, key, cfg){
          try{
            const keyStr = key && key.toString ? key.toString() : String(key);
            const ivStr = cfg && cfg.iv && cfg.iv.toString ? cfg.iv.toString() : (cfg && cfg.iv ? String(cfg.iv) : '');
            const dataStr = data && data.toString ? data.toString() : String(data);
            addRuntimeLog({ type:'AES.'+fnName, key:keyStr, iv:ivStr, data:dataStr });
            try{ if(globalThis.TREventBus) globalThis.TREventBus.emit({ type:`crypto:aes.${fnName}`, alg:'AES', keyPreview:redact(ebPreview(keyStr,80)), ivPreview:redact(ebPreview(ivStr,80)), length:dataStr.length||0, sample:redact(ebPreview(dataStr,80)), ts:Date.now() }); }catch(_e){}
          }catch(e){ logError(e); }
          return orig.apply(this, arguments);
        };
      };
      wrap('encrypt');
      wrap('decrypt');
    }catch(e){ logError(e); }
  })();

  // Hook WebSocket send/receive
  (function(){
    const OrigWS = window.WebSocket;
    if (typeof OrigWS === 'function'){
      window.WebSocket = function(...args){
        const ws = new OrigWS(...args);
        try{
          const url = args[0];
          addRuntimeLog({ type:'WS.connect', data:String(url||'') });
          const origSend = ws.send;
          ws.send = function(data){
            try{ addRuntimeLog({ type:'WS.send', data:String(data) }); }catch(e){ logError(e); }
            return origSend.apply(this, arguments);
          };
          ws.addEventListener && ws.addEventListener('message', ev=>{
            try{ addRuntimeLog({ type:'WS.recv', data:String(ev.data) }); }catch(e){ logError(e); }
          });
        }catch(e){ logError(e); }
        return ws;
      };
    }
  })();

  // Hook EventSource messages
  (function(){
    const OrigES = window.EventSource;
    if (typeof OrigES === 'function'){
      window.EventSource = function(...args){
        const es = new OrigES(...args);
        try{
          const url = args[0];
          addRuntimeLog({ type:'SSE.connect', data:String(url||'') });
          es.addEventListener && es.addEventListener('message', ev=>{
            try{ addRuntimeLog({ type:'SSE.message', data:String(ev.data) }); }catch(e){ logError(e); }
          });
        }catch(e){ logError(e); }
        return es;
      };
    }
  })();

  // Hook postMessage send/receive
  (function(){
    const origPM = window.postMessage;
    if (typeof origPM === 'function'){
      const serialize = msg => { try{ return typeof msg === 'string' ? msg : JSON.stringify(msg); }catch(e){ logError(e); return String(msg); } };
      window.postMessage = function(message, targetOrigin, transfer){
        try{ if (capturePostMessage) addRuntimeLog({ type:'postMessage.send', data:serialize(message) }); }catch(e){ logError(e); }
        return origPM.apply(this, arguments);
      };
      window.addEventListener && window.addEventListener('message', ev=>{
        try{ if (capturePostMessage) addRuntimeLog({ type:'postMessage.receive', data:serialize(ev.data), origin: ev.origin }); }catch(e){ logError(e); }
      });
    }
  })();

  // Scan globals, Web Storage and cookies for secrets
  (function(){
    const SECRET_PATTERNS = PATTERNS.filter(p=>p.key!=='URL' && p.key!=='Route');
    function matchesSecret(str){
      if (typeof str !== 'string') return false;
      for (const p of SECRET_PATTERNS){
        p.rx.lastIndex = 0;
        if (p.rx.test(str)) return true;
      }
      return false;
    }
    function scanGlobals(){
      try{
        const seen = new WeakSet();
        const nameRx = /(data|token|secret|pass|key|cfg|config)/i;
        const hexToStr = h => {
          try{
            if (h.length % 2 || /[^0-9a-f]/i.test(h)) return null;
            let out='';
            for(let i=0;i<h.length;i+=2){
              const code=parseInt(h.slice(i,i+2),16);
              if (isNaN(code)) return null;
              out+=String.fromCharCode(code);
            }
            return out;
          }catch(_e){ logError(_e); return null; }
        };
        const walk = (obj, path)=>{
          if (typeof obj === 'string'){
            if (matchesSecret(obj) || matchesSecret(path)) addRuntimeLog({ type:'global', key:path, data:obj });
            const decoded = hexToStr(obj);
            if (decoded){
              let parsed=false;
              try{ const js=JSON.parse(decoded); parsed=true; walk(js, path); }catch(_e){ logError(_e); }
              if (!parsed && matchesSecret(decoded)) addRuntimeLog({ type:'global', key:path, data:decoded });
            }
            return;
          }
          if (obj && typeof obj === 'object'){
            if (seen.has(obj)) return; seen.add(obj);
            Object.entries(obj).forEach(([k,v])=>{
              const p = path? path + '.' + k : k;
              walk(v, p);
            });
          }
        };
        Object.getOwnPropertyNames(window).forEach(name=>{
          if (!nameRx.test(name)) return;
          let val; try{ val = window[name]; }catch(_e){ logError(_e); return; }
          walk(val, name);
        });
      }catch(_e){ logError(_e); }
    }
    function scanLocalStorage(){
      try{
        for (let i=0; i<localStorage.length; i++){
          const k = localStorage.key(i);
          const v = localStorage.getItem(k);
          if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog({ type:'localStorage', key:k, data:v });
        }
      }catch(_e){ logError(_e); }
    }
    function scanSessionStorage(){
      try{
        for (let i=0; i<sessionStorage.length; i++){
          const k = sessionStorage.key(i);
          const v = sessionStorage.getItem(k);
          if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog({ type:'sessionStorage', key:k, data:v });
        }
      }catch(_e){ logError(_e); }
    }
    function scanCookies(){
      try{
        const all = (document.cookie || '').split(';');
        all.forEach(c=>{
          if (!c) return;
          const idx = c.indexOf('=');
          const k = idx>=0 ? c.slice(0,idx).trim() : c.trim();
          const v = idx>=0 ? decodeURIComponent(c.slice(idx+1)) : '';
          if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog({ type:'cookie', key:k, data:v });
        });
      }catch(_e){ logError(_e); }
    }
    const run = ()=>{ scanGlobals(); scanLocalStorage(); scanSessionStorage(); scanCookies(); };
    run();
    setTimeout(run, 1000);
  })();

  /* ============================
     CRAWLER
  ============================ */
  const tabCrawler = panel.querySelector('#tab_discover_crawler');
  const crTabBtn = panel.querySelector('#tabs_discover .ptk-tab[data-tab="crawler"]');
  tabCrawler.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Crawler (scope por dominio)</div>
        <div class="ptk-grid">
          <button id="cr_start" class="ptk-btn">Iniciar</button>
          <button id="cr_pause" class="ptk-btn">Pausar</button>
          <button id="cr_clear" class="ptk-btn">Clear</button>
          <button id="cr_copy" class="ptk-btn">Copiar JSON</button>
          <button id="cr_csv" class="ptk-btn">CSV</button>
        </div>
      </div>
      <div class="ptk-grid">
        <label>Máx páginas: <input id="cr_max" type="number" value="${CRAWL.MAX_PAGES}" min="1" style="width:84px"></label>
        <label><input type="checkbox" id="cr_follow_js" checked> Incluir .js/.json</label>
        <label><input type="checkbox" id="cr_only_same_origin" checked> Solo mismo origen</label>
      </div>
      <div style="opacity:.85">Ignora imágenes, fuentes y CSS. Extrae <code>href/src/action</code>.</div>
      <div id="cr_status" style="margin:6px 0">En espera…</div>
      <div id="cr_results"></div>
    </div>
  `;
  const crRefs = {
    start: tabCrawler.querySelector('#cr_start'),
    pause: tabCrawler.querySelector('#cr_pause'),
    clear: tabCrawler.querySelector('#cr_clear'),
    copy:  tabCrawler.querySelector('#cr_copy'),
    csv:   tabCrawler.querySelector('#cr_csv'),
    max:   tabCrawler.querySelector('#cr_max'),
    followJs: tabCrawler.querySelector('#cr_follow_js'),
    same:     tabCrawler.querySelector('#cr_only_same_origin'),
    status: tabCrawler.querySelector('#cr_status'),
    results: tabCrawler.querySelector('#cr_results')
  };
  const pillCrTxt = pill.querySelector('#pill_crawl_txt');
  const pillCrBar = pill.querySelector('#pill_crawl_bar');
  const cr = { session:0, started:false, paused:false, inFlight:0, q:[], seen:new Set(), pages:[], assets:[] };

  function crawlAllowed(url){
    if (!url) return false;
    if (IGNORE_EXT.test(url)) return false;
    if (crRefs.same.checked && !sameOrigin(url)) return false;
    if (!crRefs.followJs.checked && (SCRIPT_LIKE.test(url) || /\.json(\?|#|$)/i.test(url))) return false;
    return true;
  }
  function crawlEnqueue(url){
    const u = mkAbs(url); if (!u) return;
    let p; try{ p = new URL(u); }catch(_e){ logError(_e); return; }
    if (p.search.slice(1).length > CRAWL.MAX_QUERY_LEN) return;
    if (!crawlAllowed(u)) return;
    const norm = p.origin + p.pathname;
    if (cr.seen.has(norm)) return;
    cr.seen.add(norm); cr.q.push(u);
  }
  function crawlExtract(docText, baseUrl, ctype){
    try{
      if (/json|javascript/i.test(ctype) || /\.json(\?|#|$)/i.test(baseUrl) || SCRIPT_LIKE.test(baseUrl)) return;
      const dp = new DOMParser(); const doc = dp.parseFromString(docText, 'text/html');
      const pushAttr = (sel, attr)=> doc.querySelectorAll(sel).forEach(el => { const v = el.getAttribute(attr); if (v) crawlEnqueue(new URL(v, baseUrl).href); });
      pushAttr('a[href]', 'href'); pushAttr('[src]', 'src'); pushAttr('form[action]', 'action');
      doc.querySelectorAll('script[src]').forEach(s=>{ const u = new URL(s.getAttribute('src'), baseUrl).href; if (crawlAllowed(u)) cr.assets.push(u); });
    }catch(_e){ logError(_e); }
  }
  function crSetProgress(){
    const total = Number(crRefs.max.value)||0;
    const done = cr.pages.length;
    const pct = total? Math.min(100, Math.round(done/total*100)) : 0;
    pillCrTxt.textContent = `${done}/${total} • activos=${cr.inFlight}${cr.paused?' • PAUSADO':''}`;
    pillCrBar.style.width = pct + '%';
  }
  function crUpdateCount(){ if (crTabBtn) crTabBtn.textContent = `Crawler (${cr.pages.length})`; }
  function crRenderRow(u, status, ctype, title, note){
    const fam = family(status);
    const div = document.createElement('div'); div.className='ptk-row';
    const t = title ? ` · <b>${title}</b>` : '';
    const n = note ? ` · ${note}` : '';
    div.innerHTML = `<div><a class="ptk-link" href="${u}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${u}</a></div>
                     <div class="ptk-code" style="color:${famColor(fam)}">HTTP ${status} · ${ctype||'—'}${t}${n}</div>`;
    crRefs.results.appendChild(div);
    crUpdateCount();
  }
  function crPump(){
    if (cr.paused) return;
    if (cr.pages.length >= (Number(crRefs.max.value)||CRAWL.MAX_PAGES)) return;
    while (cr.inFlight < CRAWL.MAX_CONCURRENCY && cr.q.length && cr.pages.length < (Number(crRefs.max.value)||CRAWL.MAX_PAGES)){
      const u = cr.q.shift(); const session = cr.session; cr.inFlight++; crRefs.status.textContent = `Crawling: ${u}`;
      GM_xmlhttpRequest({
        method:'GET', url:u, timeout: CRAWL.TIMEOUT_MS, headers:{'Cache-Control':'no-cache','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.5'},
        onload: res=>{
          if (session!==cr.session) return;
          let code = res.status; const ctype = ((res.responseHeaders||'').match(/content-type:\s*([^\n\r]+)/i)||[])[1]?.trim()||'';
          const body = res.responseText||'';
          if (code>=200 && code<300 && looksLike404(body)) code=404;
          let title='';
          if (/text\/html/i.test(ctype)){ const m = body.match(/<title[^>]*>([^<]*)<\/title>/i); if (m) title = m[1].trim().slice(0,140); }
          let note='';
          if (/text\//i.test(ctype) && !/charset=/i.test(ctype)) note='sin charset';
          if (res.finalUrl && res.finalUrl !== u) note += (note?'; ':'') + `redirigido a ${res.finalUrl}`;
          cr.pages.push({ url:u, file:u, line:'', status:code, contentType: ctype, title, note, session: cr.session });
          crRenderRow(u, code, ctype, title, note);
          if (code>=200 && code<400){ crawlExtract(body, u, ctype); }
        },
        onerror: ()=>{ if (session!==cr.session) return; cr.pages.push({url:u,file:u,line:'',status:0,contentType:'',title:'',note:'Error de red',session:cr.session}); crRenderRow(u,0,'','', 'Error de red'); },
        ontimeout: ()=>{ if (session!==cr.session) return; cr.pages.push({url:u,file:u,line:'',status:0,contentType:'',title:'',note:'Timeout',session:cr.session}); crRenderRow(u,0,'','', 'Timeout'); },
        onloadend: ()=>{ if (session!==cr.session) return; cr.inFlight--; crSetProgress(); setTimeout(crPump, CRAWL.DELAY_MS); }
      });
    }
    crSetProgress();
    if (!cr.q.length && cr.inFlight===0){ crRefs.status.textContent = `Finalizado. Páginas: ${cr.pages.length} · Assets JS: ${unique(cr.assets).length}`; }
  }
  function crStart(){
    if (cr.started) return;
    cr.started=true; cr.paused=false; cr.session++; cr.inFlight=0; cr.q.length=0; cr.pages.length=0; cr.assets.length=0; cr.seen.clear();
    crRefs.results.innerHTML='';
    crUpdateCount();
    crawlEnqueue(location.href);
    ['/robots.txt','/sitemap.xml','/security.txt','/ads.txt'].forEach(p=>crawlEnqueue(location.origin+p));
    crRefs.status.textContent = 'Iniciando…'; crPump();
  }
  function crPause(){ if (!cr.started) return; cr.paused = !cr.paused; crRefs.pause.textContent = cr.paused?'Reanudar':'Pausar'; if (!cr.paused) crPump(); }
  function crClear(){ cr.paused=true; cr.started=false; cr.session++; cr.inFlight=0; cr.q.length=0; cr.pages.length=0; cr.assets.length=0; cr.seen.clear(); crRefs.results.innerHTML=''; crRefs.status.textContent='En espera…'; crRefs.pause.textContent='Pausar'; crSetProgress(); crUpdateCount(); }
  crRefs.start.onclick=crStart; crRefs.pause.onclick=crPause; crRefs.clear.onclick=crClear;
  crRefs.copy.onclick=()=>{ const out=JSON.stringify({pages:cr.pages, assets:unique(cr.assets)}, null, 2); clip(out); crRefs.copy.textContent='¡Copiado!'; setTimeout(()=>crRefs.copy.textContent='Copiar JSON',1200); };
  crRefs.csv.onclick=()=>{ const head=['file','line','url','status','contentType','title','note']; csvDownload(`crawl_pages_${nowStr()}.csv`, head, cr.pages.map(p=>({file:p.file,line:p.line,url:p.url,status:p.status,contentType:p.contentType,title:p.title||'',note:p.note||''}))); };

  /* ============================
     Source Maps / Debug Artefacts
  ============================ */
  const tabDebug = panel.querySelector('#tab_discover_debug');
  const dbgTabBtn = panel.querySelector('#tabs_discover .ptk-tab[data-tab="debug"]');
  const dbgRefs = {
    list: tabDebug.querySelector('#dbg_list'),
    fetch: tabDebug.querySelector('#dbg_fetch'),
    rescan: tabDebug.querySelector('#dbg_rescan'),
    copy: tabDebug.querySelector('#dbg_copy'),
    csv: tabDebug.querySelector('#dbg_csv'),
    limit: tabDebug.querySelector('#dbg_limit'),
    status: tabDebug.querySelector('#dbg_status'),
    results: tabDebug.querySelector('#dbg_results')
  };
  let dbgLimit = DEBUG.DEFAULT_MAX_MB;
  try{ if (typeof GM_getValue === 'function') dbgLimit = Number(GM_getValue(`${site}_dbg_limit`, DEBUG.DEFAULT_MAX_MB)); }catch(_e){}
  dbgRefs.limit.value = dbgLimit;
  dbgRefs.fetch.textContent = `Descargar y Demapear (≤${dbgLimit}MB)`;
  const dbg = { findings: [], maps: [], sources: [] };
  function fmtBytes(n){ if(n==null||isNaN(n)) return ''; const u=['B','KB','MB','GB']; let i=0; while(n>=1024&&i<u.length-1){ n/=1024; i++; } return n.toFixed(1)+u[i]; }
  function dbgRender(){
    if (dbgTabBtn) dbgTabBtn.textContent = `Source Maps / Debug Artefacts (${dbg.findings.length})`;
    dbgRefs.results.innerHTML='';
    dbg.findings.forEach(f=>{
      const div=document.createElement('div'); div.className='ptk-row';
      const st=f.status?` · ${f.status}`:'';
      const sz=f.size?` · ${fmtBytes(f.size)}${f.truncated?' (truncado)':''}`:'';
      div.innerHTML = `<div style="opacity:.8">${escHTML(f.url)}</div><div>${f.artefact}${st}${sz}</div>`;
      dbgRefs.results.appendChild(div);
    });
  }
  dbgRefs.limit.addEventListener('change',()=>{
    dbgLimit = Number(dbgRefs.limit.value)||DEBUG.DEFAULT_MAX_MB;
    dbgRefs.fetch.textContent = `Descargar y Demapear (≤${dbgLimit}MB)`;
    try{ if (typeof GM_setValue === 'function') GM_setValue(`${site}_dbg_limit`, dbgLimit); }catch(_e){}
  });
  function dbgList(){
    dbg.findings.length=0; dbg.maps.length=0; dbg.sources.length=0;
    dbgRefs.results.innerHTML=''; dbgRender();
    const resources=[...document.scripts,...document.querySelectorAll('link[rel="stylesheet"]')];
    let pending=resources.length;
    if(!pending){ dbgRefs.status.textContent='Listo'; return; }
    dbgRefs.status.textContent='Buscando…';
    const done=()=>{ if(--pending===0){ dbgRefs.status.textContent='Listo'; dbgRender(); } };
    resources.forEach(el=>{
      const url=el.src||el.href||''; if(!url){ done(); return; }
      if(/\/_next\//.test(url)) dbg.findings.push({url,status:'',size:0,artefact:'_next/'});
      if(/__webpack_hmr/.test(url)) dbg.findings.push({url,status:'',size:0,artefact:'__webpack_hmr'});
      if(/@vite|\/vite\//.test(url)) dbg.findings.push({url,status:'',size:0,artefact:'vite'});
      GM_xmlhttpRequest({method:'GET',url,timeout:DEBUG.TIMEOUT_MS,
        onload:res=>{
          const m=res.responseText.match(/[#@]\s*sourceMappingURL=([^\s\n]+)/);
          if(m){
            let mapUrl; try{ mapUrl=new URL(m[1],url).href; }catch(_e){ mapUrl=m[1]; }
            const info={url:mapUrl,status:'?',size:0,artefact:'map'};
            dbg.findings.push(info); dbg.maps.push(info);
            GM_xmlhttpRequest({method:'HEAD',url:mapUrl,timeout:DEBUG.TIMEOUT_MS,
              onload:r2=>{info.status=r2.status; const m2=(r2.responseHeaders||'').match(/content-length:\s*(\d+)/i); info.size=m2?Number(m2[1]):0; dbgRender(); done();},
              onerror:()=>{info.status='error'; dbgRender(); done();},
              ontimeout:()=>{info.status='timeout'; dbgRender(); done();}
            });
          } else done();
        },
        onerror:done,
        ontimeout:done
      });
    });
  }
  function dbgFetch(){
    if(!dbg.maps.length){ dbgRefs.status.textContent='No hay maps.'; return; }
    const maxBytes=(Number(dbgRefs.limit.value)||DEBUG.DEFAULT_MAX_MB)*1024*1024;
    dbg.sources.length=0;
    let pending=dbg.maps.length;
    dbgRefs.status.textContent='Descargando…';
    dbg.maps.forEach(info=>{
      GM_xmlhttpRequest({method:'GET',url:info.url,timeout:DEBUG.TIMEOUT_MS,
        onload:res=>{
          info.status=res.status;
          try{
            const bytes=typeof TextEncoder!=='undefined'?new TextEncoder().encode(res.responseText||'').length:(res.responseText||'').length;
            info.size=bytes;
            if(bytes>maxBytes){info.truncated=true;}else{
              const sm=JSON.parse(res.responseText);
              const base=info.url.replace(/[^/]+$/, '');
              const sroot=sm.sourceRoot||'';
              (sm.sources||[]).forEach((s,i)=>{
                const content=sm.sourcesContent&&sm.sourcesContent[i];
                if(typeof content==='string'){
                  const abs=new URL(s, base+sroot).href;
                  dbg.sources.push({file:abs, content});
                }
              });
            }
          }catch(e){logError(e);}
          if(--pending===0){dbgRefs.status.textContent='Maps procesados'; dbgRender();}
        },
        onerror:()=>{info.status='error'; if(--pending===0){dbgRefs.status.textContent='Maps procesados'; dbgRender();}},
        ontimeout:()=>{info.status='timeout'; if(--pending===0){dbgRefs.status.textContent='Maps procesados'; dbgRender();}}
      });
    });
  }
  function dbgRescan(){
    if(!dbg.sources.length){ dbgRefs.status.textContent='Sin fuentes'; return; }
    dbgRefs.status.textContent='Re-escaneando…';
    dbg.sources.forEach(src=>{ try{ jsScanText(src.file, src.content); }catch(e){ logError(e); } });
    jsRender();
    dbgRefs.status.textContent='JS Hunter actualizado';
  }
  dbgRefs.list.onclick=dbgList;
  dbgRefs.fetch.onclick=dbgFetch;
  dbgRefs.rescan.onclick=dbgRescan;
  dbgRefs.copy.onclick=()=>{ const out=JSON.stringify(dbg.findings,null,2); clip(out); dbgRefs.copy.textContent='¡Copiado!'; setTimeout(()=>dbgRefs.copy.textContent='Copiar JSON',1200); };
  dbgRefs.csv.onclick=()=>{ const head=['url','status','size','artefact']; csvDownload(`debug_maps_${nowStr()}.csv`, head, dbg.findings.map(f=>({url:f.url,status:f.status,size:f.size,artefact:f.artefact}))); };

  /* ============================
     VERSIONS (cola única, anti-stall; headers 1x/host; externos solo si referenciados)
  ============================ */
  const tabVers = panel.querySelector('#tab_security_versions');
  const versTabBtn = panel.querySelector('#tabs_security .ptk-tab[data-tab="versions"]');
  tabVers.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Version Detector (headers / filenames / comments / JS)</div>
        <div class="ptk-grid">
          <button id="vd_run" class="ptk-btn">Detectar</button>
          <button id="vd_clear" class="ptk-btn">Clear</button>
          <button id="vd_csv" class="ptk-btn">CSV</button>
        </div>
      </div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="vd_from_headers" checked> Headers (1× por host)</label>
        <label><input type="checkbox" id="vd_from_filenames" checked> Nombres de archivo</label>
        <label><input type="checkbox" id="vd_from_comments" checked> Comentarios HTML/JS</label>
        <label><input type="checkbox" id="vd_sections"> Buscar en todas las secciones (usar Crawler)</label>
      </div>
      <div id="vd_status" style="margin:6px 0">En espera…</div>
      <div id="vd_results"></div>
    </div>
  `;

  const vdRefs = {
    run: tabVers.querySelector('#vd_run'),
    clear: tabVers.querySelector('#vd_clear'),
    csv: tabVers.querySelector('#vd_csv'),
    status: tabVers.querySelector('#vd_status'),
    results: tabVers.querySelector('#vd_results'),
    hdr: tabVers.querySelector('#vd_from_headers'),
    file: tabVers.querySelector('#vd_from_filenames'),
    cm: tabVers.querySelector('#vd_from_comments'),
    sections: tabVers.querySelector('#vd_sections')
  };
  const pillVerTxt = pill.querySelector('#pill_ver_txt');
  const pillVerBar = pill.querySelector('#pill_ver_bar');

  const vd = { findings: [], seen:new Set(), session:0, total:0, done:0, active:0 };

  function vdUpdateCount(){ if (versTabBtn) versTabBtn.textContent = `Versions/Headers/Policies (${vd.findings.length})`; }

  const RX_VER = /\b(?:v|version[^\w]?|ver[^\w]?|release[^\w]?|build[^\w]?){0,1}\s*([0-9]+\.[0-9]+(?:\.[0-9]+){0,3}(?:[-_a-z0-9.]+)?)\b/gi;
  const RX_FILE_VER = /(?:jquery|react|vue|angular|bootstrap|moment|lodash|underscore|d3|leaflet|three|ckeditor|tinymce|swiper|alpine|next|nuxt|webpack|tailwind|fontawesome|sentry|amplitude|mixpanel|express|nestjs|chart|semantic|ember)[^\/]*?([0-9]+(?:\.[0-9]+){1,3})/i;

  function vdAdd(kind, tech, version, url, where, evidence, file, line){
    // Para headers dedup por host, no por URL específica
    const keyUrl = (where==='headers@host') ? (new URL(url)).host : url;
    const key = [kind,tech,version,keyUrl,where,String(line||'')].join('|');
    if (vd.seen.has(key)) return;
    vd.seen.add(key);
    vd.findings.push({ kind, tech, version, url, where, evidence, file: file||url, line: (typeof line==='number' ? (line+1) : '') });
    vdUpdateCount();
  }
  function vdRow(f){
    const div = document.createElement('div'); div.className='ptk-row';
    div.innerHTML = `<div><b>${f.kind}</b> · ${f.tech||'tech?'} · <b>${f.version||'?'}</b></div>
                     <div class="ptk-code">${f.file}${f.line?` :${f.line}`:''}</div>
                     <div class="ptk-code" style="opacity:.9">${f.url}${f.where?` · ${f.where}`:''}</div>
                     <div class="ptk-code" style="opacity:.8">${highlightEnc(escHTML(f.evidence||''))}</div>`;
    vdRefs.results.appendChild(div);
  }
  function vdSetProg(){
    const pct = vd.total ? Math.round(vd.done / vd.total * 100) : 0;
    pillVerTxt.textContent = vd.total ? `${vd.done}/${vd.total} • activos=${vd.active}` : '—';
    pillVerBar.style.width = pct + '%';
  }

  function collectExternalJsFromPage(){
    const out = [];
    document.querySelectorAll('script[src]').forEach(s=>{
      const u = mkAbs(s.getAttribute('src')||''); if (!u) return;
      if (sameOrigin(u)) return;
      if (!/\.js(\?|#|$)/i.test(u) && !/\.json(\?|#|$)/i.test(u)) return;
      out.push(u);
    });
    return unique(out);
  }

  vdRefs.run.onclick = vdRun;
  vdRefs.clear.onclick = ()=>{
    vd.findings.length=0; vd.seen.clear();
    vdRefs.results.innerHTML=''; vdRefs.status.textContent='En espera…';
    vd.total=vd.done=vd.active=0; vdSetProg();
    vdUpdateCount();
  };
  vdRefs.csv.onclick = ()=>{
    const head=['kind','tech','version','file','line','url','where','evidence'];
    csvDownload(`versions_${nowStr()}.csv`, head, vd.findings);
  };

  function vdRun(){
    vd.session++; const mySession = vd.session;
    vd.findings.length=0; vd.seen.clear(); vdUpdateCount();
    vdRefs.results.innerHTML=''; vdRefs.status.textContent='Preparando…';

    // 1) Contenido del MISMO HOST
    const urlsSame = new Set([location.href]);
    [...document.querySelectorAll('[src],[href]')].forEach(n=>{
      ['src','href'].forEach(a=>{
        const v = n.getAttribute && n.getAttribute(a); if (!v) return;
        const abs = mkAbs(v); if (!abs) return;
        if (!sameOrigin(abs)) return;
        if (IGNORE_EXT.test(abs)) return;
        urlsSame.add(abs);
      });
    });
    if (vdRefs.sections.checked){
      if (!cr.pages.length){
        vdRefs.status.textContent = 'Sin páginas del Crawler: analizaré solo esta página. Ejecuta Crawler para cubrir secciones.';
      } else {
        cr.pages.forEach(p=>{ if (sameOrigin(p.url)) urlsSame.add(p.url); });
        unique(cr.assets).forEach(a=>{ if (sameOrigin(a) && !IGNORE_EXT.test(a)) urlsSame.add(a); });
      }
    }

    // 2) Externos (.js/.json) realmente usados por la PÁGINA ACTUAL (CDN)
    const extAssets = collectExternalJsFromPage();
    const extHosts = new Map();
    extAssets.forEach(u=>{ try{ const h=new URL(u).host; if(!extHosts.has(h)) extHosts.set(h,u);}catch(e){ logError(e); } });

    // 3) Construir cola única
    //    - HEAD 1× por host (host actual + hosts externos que SÍ se usan)
    //    - GET contenido: same-host (HTML/JS) + externos (sólo JS banners y filename)
    const queue = [];
    const processedHosts = new Set();
    const processedGets  = new Set();

    if (vdRefs.hdr.checked){
      const hereHost = location.host;
      queue.push({ type:'HEAD', url: location.href, host: hereHost, where: 'headers@host' });
      processedHosts.add(hereHost);
      extHosts.forEach((repUrl, h)=>{
        if (!processedHosts.has(h)) {
          queue.push({ type:'HEAD', url: repUrl, host: h, where: 'headers@host' });
          processedHosts.add(h);
        }
      });
    }
    unique([...urlsSame]).forEach(u=>{
      if (!processedGets.has(u)){ queue.push({ type:'GET', url: u, same:true }); processedGets.add(u); }
    });
    unique(extAssets).forEach(u=>{
      if (!processedGets.has(u)){ queue.push({ type:'GET', url: u, same:false }); processedGets.add(u); }
    });

    vd.total = queue.length;
    vd.done = 0; vd.active = 0; vdSetProg();
    vdRefs.status.textContent = `Analizando 0/${vd.total}…`;

    // 4) Ejecutor concurrente robusto
    const MAXC = VERS.MAX_CONCURRENCY;
    let qi = 0;

    function finalize(){
      if (vd.session !== mySession) return; // descartado por nueva corrida
      vd.done++; vd.active--; vdRefs.status.textContent = `Analizando ${vd.done}/${vd.total}…`;
      vdSetProg();
      pump();
    }

    function pump(){
      if (vd.session !== mySession) return;
      if (vd.done >= vd.total && vd.active===0){
        vdRefs.status.textContent = `OK · hallazgos: ${vd.findings.length}`;
        vd.findings.forEach(vdRow);
        return;
      }
      while (vd.active < MAXC && qi < queue.length){
        const task = queue[qi++]; vd.active++; vdSetProg();
        if (task.type === 'HEAD'){
          const hdrUrl = task.url; // HEAD puede fallar; fallback GET range
          let finished = false;
          const finishOnce = ()=>{ if (finished) return; finished=true; finalize(); };

          GM_xmlhttpRequest({
            method:'HEAD', url: hdrUrl, timeout: VERS.TIMEOUT_MS, headers:{'Cache-Control':'no-cache'},
            onload: res=>{
              if (vd.session !== mySession) return;
              const hdr = res.responseHeaders||'';
              parseHeaderBlock(hdr, task.host, task.where);
              // Si HEAD no permitido, reintenta con GET (Range)
              if (res.status===405 || res.status===501){
                enqueueGetHeaderFallback(task.host, hdrUrl);
              }
            },
            onerror: finishOnce,
            ontimeout: finishOnce,
            onloadend: finishOnce
          });
        } else { // GET contenido
          const u = task.url;
          const isJS = /\.js(\?|#|$)/i.test(u);
          let finished = false;
          const finishOnce = ()=>{ if (finished) return; finished=true; finalize(); };

          GM_xmlhttpRequest({
            method:'GET', url: u, timeout: VERS.TIMEOUT_MS, headers:{'Cache-Control':'no-cache'},
            onload: res=>{
              if (vd.session !== mySession) return;
              const body = (res.responseText||'').slice(0, VERS.BYTES_HEAD);

              // Filename heurística
              if (vdRefs.file.checked && RX_FILE_VER.test(u)){
                const m = u.match(RX_FILE_VER); vdAdd('Filename','lib',m[1],u,'filename',u,u,'');
              }

              // Comentarios/Banners
              if (vdRefs.cm.checked){
                if (task.same){
                  // HTML
                  const htmlMatches = [...(body.matchAll(/<!--([\s\S]*?)-->/g))];
                  htmlMatches.forEach(m=>{
                    const idx = m.index || 0; const line = lineFromIndex(body, idx);
                    const vm = [...(m[0].matchAll(RX_VER))];
                    if (vm.length) vdAdd('Comment','html',vm[0][1],u,'html-comment',m[0].slice(0,180),u,line-1);
                  });
                  // JS /*! */
                  const jsb = [...(body.matchAll(/\/\*!([\s\S]{0,260})\*\//g))];
                  jsb.forEach(m=>{
                    const idx = m.index || 0; const line = lineFromIndex(body, idx);
                    const vm = [...(m[0].matchAll(RX_VER))];
                    if (vm.length) vdAdd('JS Banner','js',vm[0][1],u,'js-comment',m[0].slice(0,180),u,line-1);
                  });
                } else if (isJS){
                  const jsb = [...(body.matchAll(/\/\*!([\s\S]{0,260})\*\//g))];
                  jsb.forEach(m=>{
                    const idx = m.index || 0; const line = lineFromIndex(body, idx);
                    const vm = [...(m[0].matchAll(RX_VER))];
                    if (vm.length) vdAdd('JS Banner (ext)','js',vm[0][1],u,'js-comment',m[0].slice(0,180),u,line-1);
                  });
                }
              }
            },
            onerror: finishOnce,
            ontimeout: finishOnce,
            onloadend: finishOnce
          });
        }
      }
    }

    function parseHeaderBlock(hdr, host, where){
      const server = (hdr.match(/^\s*server:\s*(.+)$/gim)||[]).join(' | ');
      const xpow   = (hdr.match(/^\s*x-powered-by:\s*(.+)$/gim)||[]).join(' | ');
      if (server){ const m=[...server.matchAll(RX_VER)]; if (m.length) vdAdd('Header','Server',m[0][1], `https://${host}/`, where, server, `https://${host}/`, ''); }
      if (xpow){ const m=[...xpow.matchAll(RX_VER)]; if (m.length) vdAdd('Header','X-Powered-By',m[0][1], `https://${host}/`, where, xpow, `https://${host}/`, ''); }
      const other = (hdr.match(/^\s*(x-aspnet-version|x-drupal|x-runtime|x-generator):\s*(.+)$/gim)||[]);
      other.forEach(line=>{ const mm = [...line.matchAll(RX_VER)]; if (mm.length) vdAdd('Header','Header',mm[0][1], `https://${host}/`, where, line.trim(), `https://${host}/`, ''); });
    }

    function enqueueGetHeaderFallback(host, url){
      // Empuja una tarea extra para leer headers vía GET minimal (Range)
      queue.push({ type:'HEAD_FALLBACK', host, url, where:'headers@host' });
      vd.total++; vdSetProg();
      // Disparar si hay cupo
      pump();
      // Ejecutar (con su propio handler)
      const idx = queue.length - 1;
      // Nota: la cola se consume secuencialmente; no es necesario retocar qi.
      // La tarea HEAD_FALLBACK se ejecutará cuando le toque, abajo:
    }

    // Hook: convertir tareas HEAD_FALLBACK cuando aparezcan
    const _origPump = pump;
    pump = function(){
      // interceptamos: si toca HEAD_FALLBACK, la tratamos como GET range
      while (vd.active < MAXC && qi < queue.length){
        const task = queue[qi];
        if (task.type !== 'HEAD_FALLBACK') break;
        qi++; vd.active++; vdSetProg();
        let finished = false; const finishOnce = ()=>{ if (finished) return; finished=true; finalize(); };
        GM_xmlhttpRequest({
          method:'GET', url: task.url, timeout: VERS.TIMEOUT_MS,
          headers:{'Cache-Control':'no-cache','Range':'bytes=0-1'},
          onload: res=>{ if (vd.session===mySession){ parseHeaderBlock(res.responseHeaders||'', task.host, task.where); } },
          onerror: finishOnce, ontimeout: finishOnce, onloadend: finishOnce
        });
      }
      _origPump();
    };

    // Arrancamos
    pump();
  }


  /* ============================
     Cookies & Storage inventory
  ============================ */
  const tabCookies = panel.querySelector('#tab_security_cookies');
  const ckTabBtn = panel.querySelector('#tabs_security .ptk-tab[data-tab="cookies"]');
  tabCookies.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Cookies &amp; Storage Inventory</div>
        <div class="ptk-grid">
          <button id="cs_refresh" class="ptk-btn">Refresh</button>
          <button id="cs_csv" class="ptk-btn">CSV</button>
          <button id="cs_json" class="ptk-btn">JSON</button>
        </div>
      </div>
      <div id="cs_status" style="margin:6px 0">En espera…</div>
      <div id="cs_results"></div>
    </div>
  `;
  const csRefs = {
    refresh: tabCookies.querySelector('#cs_refresh'),
    csv: tabCookies.querySelector('#cs_csv'),
    json: tabCookies.querySelector('#cs_json'),
    status: tabCookies.querySelector('#cs_status'),
    results: tabCookies.querySelector('#cs_results')
  };
  const cs = { cookies: [], ls: [], ss: [], idb: [] };
  function csUpdateCount(){
    const total = cs.cookies.length + cs.ls.length + cs.ss.length + cs.idb.length;
    if (ckTabBtn) ckTabBtn.textContent = `Cookies & Storage (${total})`;
  }
  function csPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_cookies_storage`, JSON.stringify(cs)); }catch(_e){} }
  function csLoad(){ try{ if(typeof GM_getValue==='function'){ const j=GM_getValue(`${site}_cookies_storage`, 'null'); if(j) Object.assign(cs, JSON.parse(j)); } }catch(_e){} }
  function cookieRisk(c){ return (!c.secure && String(c.sameSite).toLowerCase()==='none') ? 'SameSite=None sin Secure' : ''; }
  const RX_JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
  const RX_TOKEN = /(token|jwt|bearer)/i;
  function storageRisk(k,v){ if(RX_JWT.test(v)) return 'JWT'; if(RX_TOKEN.test(k)||RX_TOKEN.test(v)) return 'token'; return ''; }
  async function scanCookies(){
    try{
      if(global.cookieStore && cookieStore.getAll){
        const list = await cookieStore.getAll();
        return list.map(c=>({
          name:c.name, domain:c.domain||location.hostname, path:c.path||'',
          secure:!!c.secure, httpOnly:!!c.httpOnly, sameSite:c.sameSite||'',
          risk:cookieRisk(c)
        }));
      }
    }catch(_e){}
    const out=[]; (document.cookie||'').split(';').forEach(c=>{
      if(!c) return; const idx=c.indexOf('='); const name=idx>=0?c.slice(0,idx).trim():c.trim();
      out.push({ name, domain:location.hostname, path:'', secure:location.protocol==='https:', httpOnly:false, sameSite:'', risk:'' });
    }); return out;
  }
  function scanWebStorage(){
    const ls=[], ss=[];
    try{
      for(let i=0;i<localStorage.length;i++){
        const k=localStorage.key(i); const v=localStorage.getItem(k)||''; const risk=storageRisk(k,v);
        ls.push({ key:k, size:v.length, preview:v.length>128? v.slice(0,128)+'…':v, risk });
      }
    }catch(_e){}
    try{
      for(let i=0;i<sessionStorage.length;i++){
        const k=sessionStorage.key(i); const v=sessionStorage.getItem(k)||''; const risk=storageRisk(k,v);
        ss.push({ key:k, size:v.length, preview:v.length>128? v.slice(0,128)+'…':v, risk });
      }
    }catch(_e){}
    return {ls, ss};
  }
  async function scanIDB(){
    const names=[]; try{ if(global.indexedDB && indexedDB.databases){ const dbs=await indexedDB.databases(); dbs.forEach(d=>{ if(d && d.name) names.push(d.name); }); } }catch(_e){}
    return names;
  }
  function csRender(){
    csRefs.results.innerHTML='';
    const cDiv=document.createElement('div'); cDiv.className='ptk-row';
    if(cs.cookies.length){
      let html='<div class="ptk-hdr">Cookies</div><table style="width:100%"><tr><th>Nombre</th><th>Dominio</th><th>Path</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Riesgo</th></tr>';
      cs.cookies.forEach(c=>{ html+=`<tr${c.risk?' style="color:#f87171"':''}><td>${escHTML(c.name)}</td><td>${escHTML(c.domain)}</td><td>${escHTML(c.path)}</td><td>${c.secure?'✓':'✗'}</td><td>${c.httpOnly?'✓':'✗'}</td><td>${escHTML(c.sameSite)}</td><td>${escHTML(c.risk)}</td></tr>`; });
      html+='</table>'; cDiv.innerHTML=html;
    }else cDiv.innerHTML='<div class="ptk-hdr">Cookies</div><div>No cookies</div>';
    csRefs.results.appendChild(cDiv);
    const sDiv=document.createElement('div'); sDiv.className='ptk-row';
    let sHtml='<div class="ptk-hdr">Web Storage</div>';
    sHtml+='<div><b>LocalStorage</b></div>';
    if(cs.ls.length){
      sHtml+='<table style="width:100%"><tr><th>Clave</th><th>Tamaño</th><th>Preview</th><th>Riesgo</th></tr>';
      cs.ls.forEach(e=>{ sHtml+=`<tr${e.risk?' style="color:#f87171"':''}><td>${escHTML(e.key)}</td><td>${e.size}</td><td class="ptk-code">${escHTML(e.preview)}</td><td>${escHTML(e.risk)}</td></tr>`; });
      sHtml+='</table>';
    }else sHtml+='<div>Vacío</div>';
    sHtml+='<div><b>SessionStorage</b></div>';
    if(cs.ss.length){
      sHtml+='<table style="width:100%"><tr><th>Clave</th><th>Tamaño</th><th>Preview</th><th>Riesgo</th></tr>';
      cs.ss.forEach(e=>{ sHtml+=`<tr${e.risk?' style="color:#f87171"':''}><td>${escHTML(e.key)}</td><td>${e.size}</td><td class="ptk-code">${escHTML(e.preview)}</td><td>${escHTML(e.risk)}</td></tr>`; });
      sHtml+='</table>';
    }else sHtml+='<div>Vacío</div>';
    sHtml+='<div><b>IndexedDB</b></div>';
    if(cs.idb.length){ sHtml+='<ul>'+cs.idb.map(n=>`<li>${escHTML(n)}</li>`).join('')+'</ul>'; } else sHtml+='<div>No disponible</div>';
    sDiv.innerHTML=sHtml; csRefs.results.appendChild(sDiv);
  }
  async function csRefresh(){
    csRefs.status.textContent='Escaneando…';
    cs.cookies=await scanCookies();
    const ws=scanWebStorage(); cs.ls=ws.ls; cs.ss=ws.ss;
    cs.idb=await scanIDB();
    csRender(); csUpdateCount(); csPersist();
    csRefs.status.textContent='OK';
  }
  csLoad(); csRender(); csUpdateCount();
  csRefs.refresh.onclick=csRefresh;
  csRefs.csv.onclick=()=>{ if(cs.cookies.length){ const head=['name','domain','path','secure','httpOnly','sameSite','risk']; csvDownload(`cookies_${nowStr()}.csv`, head, cs.cookies); } };
  csRefs.json.onclick=()=>{ const out={localStorage:cs.ls, sessionStorage:cs.ss, indexedDB:cs.idb}; textDownload(`storage_${nowStr()}.json`, JSON.stringify(out,null,2)); };

  /* ============================
     TLS & certificate info
  ============================ */
  const tabTLS = panel.querySelector('#tab_security_tls');
  const tlsTabBtn = panel.querySelector('#tabs_security .ptk-tab[data-tab="tls"]');
  tabTLS.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">TLS &amp; Subdomains</div>
        <div class="ptk-grid">
          <button id="tls_run" class="ptk-btn">Resolver</button>
          <button id="tls_csv" class="ptk-btn">CSV</button>
          <label><input type="checkbox" id="tls_safe" checked> Safe Mode</label>
        </div>
      </div>
      <div id="tls_status" style="margin:6px 0">En espera…</div>
      <div id="tls_results"></div>
    </div>
  `;
  const tlsRefs = {
    run: tabTLS.querySelector('#tls_run'),
    csv: tabTLS.querySelector('#tls_csv'),
    safe: tabTLS.querySelector('#tls_safe'),
    status: tabTLS.querySelector('#tls_status'),
    results: tabTLS.querySelector('#tls_results')
  };
  const tlsData = { findings: [], sans: [], info:{} };
  function tlsUpdateCount(){ if (tlsTabBtn) tlsTabBtn.textContent = `TLS (${tlsData.findings.length + tlsData.sans.length})`; }
  function tlsPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_tls_info`, JSON.stringify(tlsData)); }catch(_e){} }
  function tlsLoad(){ try{ if(typeof GM_getValue==='function'){ const j=GM_getValue(`${site}_tls_info`, 'null'); if(j) Object.assign(tlsData, JSON.parse(j)); } }catch(_e){} }
  function collectDomains(){
    const set=new Set([location.hostname]);
    document.querySelectorAll('[src],[href]').forEach(el=>{
      ['src','href'].forEach(a=>{
        const v=el.getAttribute && el.getAttribute(a); if(!v) return;
        try{ const u=new URL(v,location.href); set.add(u.hostname); }catch(_e){}
      });
    });
    return Array.from(set);
  }
  function tlsRender(){
    tlsRefs.results.innerHTML='';
    if(tlsData.info){
      const div=document.createElement('div'); div.className='ptk-row';
      const proto=tlsData.info.nextHop||'';
      const ver=tlsData.info.version||'n/d';
      const cip=tlsData.info.cipher||'';
      div.textContent = `TLS: ${ver}${cip?` ${cip}`:''} · HTTP: ${proto||'n/d'}`;
      tlsRefs.results.appendChild(div);
      if(!tlsData.info.version){ const note=document.createElement('div'); note.className='ptk-row'; note.textContent='(mejor esfuerzo: versión/cifrado no expuestos)'; tlsRefs.results.appendChild(note); }
    }
    tlsData.findings.forEach(f=>{
      const div=document.createElement('div'); div.className='ptk-row';
      const exp=f.expires?` · exp=${f.expires}`:'';
      div.innerHTML = `<div><b>${escHTML(f.type)}</b> ${escHTML(f.name)} → <span class="ptk-code">${escHTML(f.value||'')}</span> (${escHTML(f.source)})${exp}</div>`;
      tlsRefs.results.appendChild(div);
    });
    tlsRefs.status.textContent = `OK · hallazgos: ${tlsData.findings.length}`;
  }
  async function dohQuery(provider, name, type){
    const url = provider==='google'
      ? `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
      : `https://1.1.1.1/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const headers = provider==='google'?{}:{'Accept':'application/dns-json'};
    return new Promise(res=>{
      if(typeof GM_xmlhttpRequest==='function'){
        GM_xmlhttpRequest({method:'GET',url,headers,onload:r=>{try{res(JSON.parse(r.responseText));}catch(_e){res(null);}},onerror:()=>res(null)});
      }else{
        fetch(url,{headers}).then(r=>r.json()).then(res).catch(()=>res(null));
      }
    });
  }
  async function crtQuery(domain){
    const url=`https://crt.sh/?q=${encodeURIComponent('%.'+domain)}&output=json`;
    return new Promise(res=>{
      if(typeof GM_xmlhttpRequest==='function'){
        GM_xmlhttpRequest({method:'GET',url,onload:r=>{try{res(JSON.parse(r.responseText));}catch(_e){res([]);}},onerror:()=>res([])});
      }else{
        fetch(url).then(r=>r.json()).then(res).catch(()=>res([]));
      }
    });
  }
  async function tlsRun(){
    tlsData.findings=[]; tlsData.sans=[]; tlsData.info={};
    tlsRefs.status.textContent='Resolviendo…';
    const nav=global.performance && global.performance.getEntriesByType && global.performance.getEntriesByType('navigation')[0];
    tlsData.info.nextHop=nav && nav.nextHopProtocol || '';
    if(nav && nav.secureConnectionStart>0) tlsData.info.version='present';
    const domains = tlsRefs.safe.checked ? [location.hostname] : collectDomains();
    for(const d of domains){
      const resp = await Promise.all([
        dohQuery('google',d,'A'),dohQuery('google',d,'AAAA'),dohQuery('google',d,'CNAME'),
        dohQuery('cloudflare',d,'A'),dohQuery('cloudflare',d,'AAAA'),dohQuery('cloudflare',d,'CNAME')
      ]);
      resp.forEach((r,idx)=>{
        const src = idx<3 ? 'dns.google' : '1.1.1.1';
        if(r && r.Answer){ r.Answer.forEach(a=>{ const t={1:'A',28:'AAAA',5:'CNAME'}[a.type]; if(t) tlsData.findings.push({type:t,name:d,value:a.data,source:src}); }); }
      });
    }
    const crt = await crtQuery(location.hostname);
    const seen=new Set();
    crt.forEach(c=>{
      const exp=c.not_after ? c.not_after.split(' ')[0] : '';
      String(c.name_value||'').split('\n').forEach(n=>{
        const name=n.trim(); if(!name || seen.has(name)) return;
        seen.add(name); tlsData.sans.push({name,source:'crt.sh',expires:exp});
        tlsData.findings.push({type:'SAN',name,value:'',source:'crt.sh',expires:exp});
      });
    });
    tlsRender(); tlsUpdateCount(); tlsPersist();
  }
  tlsRefs.run.onclick=tlsRun;
  tlsRefs.csv.onclick=()=>{ const head=['name','source','expires']; csvDownload(`tls_subdomains_${nowStr()}.csv`, head, tlsData.sans); };
  tlsLoad(); if(tlsData.findings.length){ tlsRender(); tlsUpdateCount(); }

  /* ============================
     ServiceWorkers & Cache
  ============================ */
  const tabSW = panel.querySelector('#tab_security_sw');
  const swTabBtn = panel.querySelector('#tabs_security .ptk-tab[data-tab="sw"]');
  tabSW.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Service Workers &amp; CacheStorage</div>
        <div class="ptk-grid">
          <button id="sc_refresh" class="ptk-btn">Refresh</button>
          <button id="sc_clear" class="ptk-btn">Clear</button>
          <button id="sc_csv" class="ptk-btn">CSV</button>
          <input type="text" id="sc_search" placeholder="Buscar" style="width:120px">
        </div>
      </div>
      <div id="sc_status" style="margin:6px 0">En espera…</div>
      <div id="sc_results"></div>
    </div>
  `;
  const scRefs={refresh:tabSW.querySelector('#sc_refresh'),clear:tabSW.querySelector('#sc_clear'),csv:tabSW.querySelector('#sc_csv'),search:tabSW.querySelector('#sc_search'),status:tabSW.querySelector('#sc_status'),results:tabSW.querySelector('#sc_results')};
  const scData={entries:[]};
  function scUpdateCount(){ if(swTabBtn) swTabBtn.textContent=`SW & Cache (${scData.entries.length})`; }
  function scPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_sw_cache`, JSON.stringify(scData.entries)); }catch(_e){} }
  function scLoad(){ try{ if(typeof GM_getValue==='function'){ const j=GM_getValue(`${site}_sw_cache`, 'null'); if(j) scData.entries = JSON.parse(j); } }catch(_e){} }
  function scRender(){
    scRefs.results.innerHTML='';
    const q=(scRefs.search.value||'').toLowerCase();
    scData.entries.forEach(e=>{
      const line=JSON.stringify(e).toLowerCase();
      if(q && !line.includes(q)) return;
      const div=document.createElement('div'); div.className='ptk-row';
      if(e.kind==='sw'){
        div.innerHTML=`<div><b>SW</b> <span class="ptk-code">${escHTML(e.scriptURL||'')}</span> · scope=${escHTML(e.scope||'')} · state=${escHTML(e.state||'')}</div>`;
      }else{
        const risk=/Authorization|Set-Cookie/i.test(e.flags||'')?' style="color:#f87171"':'';
        div.innerHTML=`<div${risk}><b>Cache</b> [${escHTML(e.cache)}] <a class="ptk-link" href="${e.url}" target="_blank" rel="noopener noreferrer">${escHTML(e.url)}</a>${e.size?` · ${escHTML(e.size)}`:''}${e.flags?` · ${escHTML(e.flags)}`:''}</div>`;
      }
      scRefs.results.appendChild(div);
    });
    scRefs.status.textContent=`${scData.entries.length?`Total: ${scData.entries.length}`:'En espera…'}`;
  }
  async function scRefresh(){
    scRefs.status.textContent='Escaneando…';
    scData.entries=[];
    try{
      if(navigator.serviceWorker && navigator.serviceWorker.getRegistrations){
        const regs=await navigator.serviceWorker.getRegistrations();
        regs.forEach(r=>{
          const state=r.active?'active':(r.waiting?'waiting':(r.installing?'installing':''));
          scData.entries.push({kind:'sw',scriptURL:(r.active&&r.active.scriptURL)||(r.waiting&&r.waiting.scriptURL)||(r.installing&&r.installing.scriptURL)||'',scope:r.scope||'',state});
        });
      }
    }catch(_e){}
    try{
      if(caches){
        const names=await caches.keys();
        for(const name of names){
          const cache=await caches.open(name);
          const reqs=await cache.keys();
          const resps=await cache.matchAll();
          for(let i=0;i<reqs.length && i<200;i++){
            const req=reqs[i]; const res=resps[i];
            let flags=[];
            try{ if(req.headers && req.headers.get('authorization')) flags.push('Authorization'); }catch(_e){}
            try{ if(res && res.headers && res.headers.get('set-cookie')) flags.push('Set-Cookie'); }catch(_e){}
            try{ const ct=res && res.headers && res.headers.get('content-type') || ''; if(/json/i.test(ct)) flags.push('JSON'); }catch(_e){}
            const size=(res && res.headers && res.headers.get('content-length'))||'';
            scData.entries.push({kind:'cache',cache:name,url:req.url,flags:flags.join(','),size});
          }
        }
      }
    }catch(_e){}
    scRender(); scUpdateCount(); scPersist();
    scRefs.status.textContent='OK';
  }
  scRefs.refresh.onclick=scRefresh;
  scRefs.clear.onclick=()=>{ scData.entries=[]; scRender(); scUpdateCount(); scPersist(); };
  scRefs.csv.onclick=()=>{ const head=['kind','scriptURL','scope','state','cache','url','flags','size']; csvDownload(`sw_cache_${nowStr()}.csv`, head, scData.entries); };
  scRefs.search.addEventListener('input', scRender);
  scLoad(); scRender(); scUpdateCount();

  /* ============================
     OpenAPI/Swagger discovery
  ============================ */
  const tabOA = panel.querySelector('#tab_apis_openapi');
  const oaTabBtn = panel.querySelector('#tabs_apis .ptk-tab[data-tab="openapi"]');
  tabOA.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">OpenAPI/Swagger</div>
        <div class="ptk-grid">
          <button id="oa_scan" class="ptk-btn">Detectar + Probar</button>
          <button id="oa_clear" class="ptk-btn">Clear</button>
          <button id="oa_csv" class="ptk-btn">CSV</button>
          <label><input type="checkbox" id="oa_safe" checked> Safe Mode</label>
        </div>
      </div>
      <div id="oa_status" style="margin:6px 0">En espera…</div>
      <div id="oa_results"></div>
    </div>
  `;
  const oaRefs = {
    scan: tabOA.querySelector('#oa_scan'), clear: tabOA.querySelector('#oa_clear'),
    csv: tabOA.querySelector('#oa_csv'), safe: tabOA.querySelector('#oa_safe'),
    status: tabOA.querySelector('#oa_status'), results: tabOA.querySelector('#oa_results')
  };
  const OA = { TIMEOUT_MS:8000, MAX_CONCURRENCY:4, DELAY_MS:200 };
  const oa = { queue:[], findings:[], idx:0, inFlight:0, session:0 };
  try{ if(typeof GM_getValue==='function') oa.findings=JSON.parse(GM_getValue(`${site}_openapi`, '[]'))||[]; }catch(_e){}
  oa.findings.forEach(f=>oaRender(f));
  oaUpdateCount();
  try{ if(typeof GM_getValue==='function') oaRefs.safe.checked=GM_getValue(`${site}_openapi_safe`, true); }catch(_e){}
  oaRefs.safe.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_openapi_safe`, oaRefs.safe.checked); }catch(_e){} };
  function oaUpdateCount(){ if(oaTabBtn) oaTabBtn.textContent=`OpenAPI/Swagger (${oa.findings.length})`; }
  function oaPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_openapi`, JSON.stringify(oa.findings)); }catch(_e){} }
  function oaRender(f){ const fam=family(f.status); const div=document.createElement('div'); div.className='ptk-row'; div.innerHTML=`<div><b>${f.method}</b> <a class="ptk-link" href="${f.url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${f.url}</a></div><div class="ptk-code" style="color:${famColor(fam)}">HTTP ${f.status} · ${f.ms}ms · ${f.headers}</div>`; oaRefs.results.appendChild(div); }
  function oaAddFinding(url,method,status,ms,headers){ const rec={url,method,status,ms,headers}; oa.findings.push(rec); oaRender(rec); oaUpdateCount(); oaPersist(); }
  function oaKeyHeaders(h){ const ct=/content-type:\s*([^\n\r]+)/i.exec(h); const allow=/allow:\s*([^\n\r]+)/i.exec(h); const server=/server:\s*([^\n\r]+)/i.exec(h); const a=[]; if(ct) a.push(`CT:${ct[1].trim()}`); if(allow) a.push(`Allow:${allow[1].trim()}`); if(server) a.push(`Server:${server[1].trim()}`); return a.join(' | '); }
  function oaCandidates(){
    const base=['/swagger.json','/swagger/v1/swagger.json','/swagger/v2/swagger.json','/v1/swagger.json','/v2/swagger.json','/openapi.json','/v1/openapi.json','/v2/openapi.json','/api/swagger.json','/api/openapi.json','/api-docs','/v3/api-docs','/v2/api-docs'];
    const fromDOM=[...document.querySelectorAll('a[href],link[href],script[src]')]
      .map(n=>n.getAttribute('href')||n.getAttribute('src')||'')
      .filter(v=>/swagger|openapi|api-docs/i.test(v||''))
      .map(v=>v.replace(/#.*/,''));
    return unique([...base,...fromDOM]).map(s=>/^https?:/i.test(s)?s:'/'+s.replace(/^\/+/,''));
  }
  function oaQueueFromSpec(specUrl, spec){ const base=(spec.servers&&spec.servers[0]&&spec.servers[0].url)||specUrl; Object.keys(spec.paths||{}).forEach(p=>{ if(/\{/.test(p)) return; let abs; try{ abs=new URL(p, base).href; }catch(_e){ return; } if(!sameOrigin(abs)) return; oa.queue.push({url:abs,method:'GET'}); oa.queue.push({url:abs,method:'HEAD'}); }); }
  function oaFetchSpecs(done){ const seeds=oaCandidates(); if(!seeds.length){ done(); return; } let pending=seeds.length; seeds.forEach(s=>{ const url=mkAbs(s); if(!url||!sameOrigin(url)){ if(--pending===0) done(); return; } GM_xmlhttpRequest({ method:'GET', url, timeout:OA.TIMEOUT_MS, onload:res=>{ if(res.status===200){ try{ const spec=JSON.parse(res.responseText); oaQueueFromSpec(url, spec); }catch(_e){} } }, onerror:()=>{}, ontimeout:()=>{}, onloadend:()=>{ if(--pending===0) done(); } }); }); }
  function oaPump(){ if(oa.idx>=oa.queue.length && oa.inFlight===0){ oaRefs.status.textContent=`Finalizado. Endpoints: ${oa.queue.length/2}`; return; } while(oa.inFlight<OA.MAX_CONCURRENCY && oa.idx<oa.queue.length){ const {url,method}=oa.queue[oa.idx++]; const t0=performance.now(); oa.inFlight++; oaRefs.status.textContent=`${method} ${url}`; GM_xmlhttpRequest({ method, url, timeout:OA.TIMEOUT_MS, onload:res=>{ const ms=Math.round(performance.now()-t0); const hdr=oaKeyHeaders(res.responseHeaders||''); oaAddFinding(url,method,res.status,ms,hdr); }, onerror:()=>{ const ms=Math.round(performance.now()-t0); oaAddFinding(url,method,'ERR',ms,''); }, ontimeout:()=>{ const ms=Math.round(performance.now()-t0); oaAddFinding(url,method,'TIMEOUT',ms,''); }, onloadend:()=>{ oa.inFlight--; setTimeout(oaPump, OA.DELAY_MS); } }); } }
  function oaStart(){ oa.queue=[]; oa.idx=0; oa.inFlight=0; oa.session++; oaRefs.results.innerHTML=''; oa.findings.length=0; oaUpdateCount(); oaPersist(); oaRefs.status.textContent='Buscando specs...'; oaFetchSpecs(()=>{ if(!oa.queue.length){ oaRefs.status.textContent='Sin specs válidos'; return; } oaRefs.status.textContent=`Probando ${oa.queue.length} requests...`; oaPump(); }); }
  function oaClear(){ oa.queue=[]; oa.findings.length=0; oa.idx=0; oa.inFlight=0; oaRefs.results.innerHTML=''; oaRefs.status.textContent='En espera…'; oaUpdateCount(); oaPersist(); }
  oaRefs.scan.onclick=oaStart; oaRefs.clear.onclick=oaClear; oaRefs.csv.onclick=()=>{ const head=['url','method','status','ms','headers']; csvDownload(`openapi_${nowStr()}.csv`, head, oa.findings); };

  /* ============================
     GraphQL discovery & introspection
  ============================ */
  const tabGQL = panel.querySelector('#tab_apis_graphql');
  const gqlTabBtn = panel.querySelector('#tabs_apis .ptk-tab[data-tab="graphql"]');
  tabGQL.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">GraphQL</div>
        <div class="ptk-grid">
          <button id="gql_scan" class="ptk-btn">Detectar + Probar</button>
          <button id="gql_clear" class="ptk-btn">Clear</button>
          <button id="gql_copy" class="ptk-btn">Copiar JSON</button>
          <button id="gql_csv" class="ptk-btn">CSV</button>
          <label><input type="checkbox" id="gql_introspect"> Permitir introspección</label>
        </div>
      </div>
      <div id="gql_status" style="margin:6px 0">En espera…</div>
      <div id="gql_results"></div>
    </div>
  `;
  const gqlRefs = {
    scan: tabGQL.querySelector('#gql_scan'),
    clear: tabGQL.querySelector('#gql_clear'),
    copy: tabGQL.querySelector('#gql_copy'),
    csv: tabGQL.querySelector('#gql_csv'),
    introspect: tabGQL.querySelector('#gql_introspect'),
    status: tabGQL.querySelector('#gql_status'),
    results: tabGQL.querySelector('#gql_results')
  };
  const GQL = { TIMEOUT_MS:8000 };
  const gql = { findings:[] };
  try{ if(typeof GM_getValue==='function') gql.findings=JSON.parse(GM_getValue(`${site}_graphql`, '[]'))||[]; }catch(_e){}
  function gqlUpdateCount(){ if(gqlTabBtn) gqlTabBtn.textContent=`GraphQL (${gql.findings.length})`; }
  function gqlPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_graphql`, JSON.stringify(gql.findings)); }catch(_e){} }
  function gqlRender(){
    gqlRefs.results.innerHTML='';
    gql.findings.forEach(f=>{
      const fam=family(f.status);
      const flags=[];
      if(f.introspectionEnabled) flags.push('introspectionEnabled');
      if(f.unboundedPagination) flags.push('paginación sin tope');
      const div=document.createElement('div'); div.className='ptk-row';
      div.innerHTML=`<div><a class="ptk-link" href="${f.url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${f.url}</a></div><div class="ptk-code" style="color:${famColor(fam)}">HTTP ${f.status}${flags.length?' · '+flags.join(', '):''}</div>`;
      gqlRefs.results.appendChild(div);
      if(f.queries.length || f.mutations.length || f.types.length){
        const info=document.createElement('div'); info.className='ptk-row';
        info.innerHTML=`<div class="ptk-code">Query: ${f.queries.join(', ')||'—'} | Mutation: ${f.mutations.join(', ')||'—'} | Types: ${f.types.slice(0,5).join(', ')||'—'}</div>`;
        gqlRefs.results.appendChild(info);
      }
      if(f.samples && f.samples.length){
        const pre=document.createElement('pre'); pre.className='ptk-code'; pre.textContent=f.samples.join('\n');
        gqlRefs.results.appendChild(pre);
      }
    });
    gqlUpdateCount();
  }
  gqlRender();
  try{ if(typeof GM_getValue==='function') gqlRefs.introspect.checked=GM_getValue(`${site}_graphql_introspect`, false); }catch(_e){}
  gqlRefs.introspect.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_graphql_introspect`, gqlRefs.introspect.checked); }catch(_e){} };
  function gqlCandidates(){
    const set=new Set();
    try{
      (globalThis.TRCore&&TRCore.records||[]).forEach(r=>{
        if(!r||!r.url) return;
        const base=r.url.split('?')[0];
        if(/\/graphql/i.test(base)) set.add(base);
        else if(r.response&&typeof r.response.body==='string'&&/"errors"\s*:\s*\[/i.test(r.response.body)) set.add(base);
      });
    }catch(_e){}
    ['/graphql','/api/graphql','/v1/graphql','/v2/graphql'].forEach(p=>{ const u=mkAbs(p); if(u&&sameOrigin(u)) set.add(u); });
    return Array.from(set);
  }
  const INTROSPECTION_QUERY=`query IntrospectionQuery{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name defaultValue} type{kind name ofType{kind name ofType{kind name}}}}}}}`;
  function parseIntrospection(data){
    const schema=data.__schema||{};
    const qName=schema.queryType&&schema.queryType.name;
    const mName=schema.mutationType&&schema.mutationType.name;
    const types=(schema.types||[]).map(t=>t.name).filter(Boolean);
    const queries=[]; const mutations=[]; let unbounded=false; const samples=[];
    function isList(t){ return t && (t.kind==='LIST' || (t.kind==='NON_NULL' && isList(t.ofType))); }
    const findType=name=>(schema.types||[]).find(t=>t.name===name)||{};
    const qType=findType(qName);
    if(qType.fields){
      qType.fields.forEach(f=>{
        queries.push(f.name);
        const list=isList(f.type);
        if(list){ const hasLimit=(f.args||[]).some(a=>/limit|first|pageSize/i.test(a.name)); if(!hasLimit) unbounded=true; }
      });
      for(const f of qType.fields){ if(samples.length>=2) break; const args=f.args||[]; let arg=''; if(args.some(a=>/limit|first/i.test(a.name))) arg='(limit:1)'; else if(args.length) continue; samples.push(`{ ${f.name}${arg} { __typename } }`); }
    }
    const mType=findType(mName);
    if(mType.fields) mutations.push(...mType.fields.map(f=>f.name));
    return {queries, mutations, types, unbounded, samples};
  }
  function runIntrospection(url,finding){
    GM_xmlhttpRequest({ method:'POST', url, timeout:GQL.TIMEOUT_MS, headers:{'Content-Type':'application/json','Accept':'application/json'}, data:JSON.stringify({query:INTROSPECTION_QUERY}), onload:res=>{
      try{ const json=JSON.parse(res.responseText); if(json.data){ const p=parseIntrospection(json.data); Object.assign(finding,{introspectionEnabled:true,allowIntrospection:true,queries:p.queries,mutations:p.mutations,types:p.types,samples:p.samples,unboundedPagination:p.unbounded}); } }catch(_e){}
      gqlRender(); gqlPersist();
    }, onerror:()=>{ gqlRender(); gqlPersist(); }, ontimeout:()=>{ gqlRender(); gqlPersist(); } });
  }
  function gqlStart(){
    gql.findings.length=0; gqlRender(); gqlPersist(); const cands=gqlCandidates(); if(!cands.length){ gqlRefs.status.textContent='Sin endpoints'; return; }
    gqlRefs.status.textContent=`Probando ${cands.length} endpoints...`;
    let pending=cands.length;
    cands.forEach(url=>{
      const qurl=url.includes('?')?url:url+`?query=${encodeURIComponent('{__typename}')}`;
      GM_xmlhttpRequest({ method:'GET', url:qurl, timeout:GQL.TIMEOUT_MS, headers:{'Accept':'application/json'}, onload:res=>{
        const body=res.responseText||''; const f={url, status:res.status, introspectionEnabled:false, allowIntrospection:false, queries:[], mutations:[], types:[], samples:[], unboundedPagination:false};
        if(/"errors"\s*:\s*\[/i.test(body)) f.note='errors';
        gql.findings.push(f);
        if(gqlRefs.introspect.checked && res.status===200) runIntrospection(url,f);
      }, onerror:()=>{ gql.findings.push({url,status:0,introspectionEnabled:false,allowIntrospection:false,queries:[],mutations:[],types:[],samples:[],unboundedPagination:false}); }, ontimeout:()=>{ gql.findings.push({url,status:0,introspectionEnabled:false,allowIntrospection:false,queries:[],mutations:[],types:[],samples:[],unboundedPagination:false}); }, onloadend:()=>{ if(--pending===0){ gqlRender(); gqlPersist(); gqlRefs.status.textContent=`Finalizado. Endpoints: ${cands.length}`; } } });
    });
  }
  function gqlClear(){ gql.findings.length=0; gqlRender(); gqlPersist(); gqlRefs.status.textContent='En espera…'; }
  gqlRefs.scan.onclick=gqlStart; gqlRefs.clear.onclick=gqlClear;
  gqlRefs.copy.onclick=()=>{ const out=JSON.stringify(gql.findings,null,2); clip(out); gqlRefs.copy.textContent='¡Copiado!'; setTimeout(()=>gqlRefs.copy.textContent='Copiar JSON',1200); };
  gqlRefs.csv.onclick=()=>{ const rows=[]; gql.findings.forEach(f=>f.types.forEach(t=>rows.push({url:f.url,type:t}))); const head=['url','type']; csvDownload(`graphql_types_${nowStr()}.csv`, head, rows); };

  /* ============================
     CORS Tester
  ============================ */
  const tabCORS = panel.querySelector('#tab_apis_cors');
  const coTabBtn = panel.querySelector('#tabs_apis .ptk-tab[data-tab="cors"]');
  tabCORS.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">CORS Tester</div>
        <div class="ptk-grid">
          <button id="co_run" class="ptk-btn">Probar</button>
          <button id="co_clear" class="ptk-btn">Clear</button>
          <button id="co_csv" class="ptk-btn">CSV</button>
          <label><input type="checkbox" id="co_cred"> Incluir credenciales</label>
          <label><input type="checkbox" id="co_safe" checked> Safe Mode</label>
        </div>
      </div>
      <div class="ptk-row"><label>Endpoints<br><textarea id="co_targets" rows="3" style="width:100%"></textarea></label></div>
      <div id="co_status" style="margin:6px 0">En espera…</div>
      <div id="co_results"></div>
    </div>
  `;
  const coRefs = {
    run: tabCORS.querySelector('#co_run'),
    clear: tabCORS.querySelector('#co_clear'),
    csv: tabCORS.querySelector('#co_csv'),
    cred: tabCORS.querySelector('#co_cred'),
    safe: tabCORS.querySelector('#co_safe'),
    targets: tabCORS.querySelector('#co_targets'),
    status: tabCORS.querySelector('#co_status'),
    results: tabCORS.querySelector('#co_results')
  };
  const CO = { TIMEOUT_MS:8000, MAX_CONCURRENCY:4, DELAY_MS:200 };
  const co = { queue:[], findings:[], idx:0, inFlight:0, session:0 };
  try{ if(typeof GM_getValue==='function') coRefs.targets.value=GM_getValue(`${site}_cors_targets`,''); }catch(_e){}
  coRefs.targets.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_cors_targets`, coRefs.targets.value); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') coRefs.cred.checked=GM_getValue(`${site}_cors_cred`, false); }catch(_e){}
  coRefs.cred.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_cors_cred`, coRefs.cred.checked); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') coRefs.safe.checked=GM_getValue(`${site}_cors_safe`, true); }catch(_e){}
  coRefs.safe.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_cors_safe`, coRefs.safe.checked); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') co.findings=JSON.parse(GM_getValue(`${site}_cors`, '[]'))||[]; }catch(_e){}
  co.findings.forEach(f=>coRender(f));
  coUpdateCount();
  function coUpdateCount(){ if(coTabBtn) coTabBtn.textContent=`CORS Tester (${co.findings.length})`; }
  function coPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_cors`, JSON.stringify(co.findings)); }catch(_e){} }
  function coRender(f){
    const fam=family(f.status);
    const risk=f.risk?' ⚠️':'';
    const div=document.createElement('div');
    div.className='ptk-row';
    div.innerHTML=`<div><b>${f.method}</b> <span>${escHTML(f.origin)}</span> <a class="ptk-link" href="${f.url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${f.url}</a>${risk}</div><div class="ptk-code" style="color:${famColor(fam)}">HTTP ${f.status} · ACAO=${escHTML(f.acao||'')} ACAC=${escHTML(f.acac||'')} Vary=${escHTML(f.vary||'')} ACAH=${escHTML(f.acah||'')} ACAM=${escHTML(f.acam||'')}</div>`;
    coRefs.results.appendChild(div);
  }
  function coTargets(){
    return unique(coRefs.targets.value.split(/\s+/).map(s=>s.trim()).filter(Boolean).map(p=>mkAbs(p)).filter(Boolean).filter(u=>!coRefs.safe.checked||sameOrigin(u)));
  }
  function coStart(){
    const targets=coTargets();
    if(!targets.length){ coRefs.status.textContent='Sin endpoints'; return; }
    co.queue=[]; co.idx=0; co.inFlight=0; co.session++; co.findings.length=0; coRefs.results.innerHTML=''; coUpdateCount(); coPersist();
    const rndSub=`https://${Math.random().toString(36).slice(2)}.${location.hostname}`;
    targets.forEach(url=>{
      ['OPTIONS','GET','HEAD'].forEach(method=>{
        [
          {label:'null',value:'null'},
          {label:'sub',value:rndSub},
          {label:'ext',value:'https://evil.example'},
          {label:'same',value:location.origin}
        ].forEach(o=>co.queue.push({url,method,origin:o}));
      });
    });
    coRefs.status.textContent=`Probando ${co.queue.length} requests...`;
    coPump();
  }
  function coAddFinding(rec){ co.findings.push(rec); coRender(rec); coUpdateCount(); coPersist(); }
  function coPump(){
    if(co.idx>=co.queue.length && co.inFlight===0){ coRefs.status.textContent=`Finalizado. Tests: ${co.queue.length}`; return; }
    while(co.inFlight<CO.MAX_CONCURRENCY && co.idx<co.queue.length){
      const q=co.queue[co.idx++]; const t0=performance.now(); co.inFlight++; coRefs.status.textContent=`${q.method} ${q.origin.label} ${q.url}`;
      const headers={'Origin':q.origin.value}; if(q.method==='OPTIONS'){ headers['Access-Control-Request-Method']='POST'; }
      GM_xmlhttpRequest({ method:q.method, url:q.url, timeout:CO.TIMEOUT_MS, withCredentials:coRefs.cred.checked, headers,
        onload:res=>{
          const hdr=res.responseHeaders||''; const grab=n=>{ const m=new RegExp('^'+n+':\s*([^\n]+)','im').exec(hdr); return m?m[1].trim():''; };
          const acao=grab('access-control-allow-origin'); const acac=grab('access-control-allow-credentials');
          const vary=grab('vary'); const acah=grab('access-control-allow-headers'); const acam=grab('access-control-allow-methods');
          const risk=(acao==='*' && (coRefs.cred.checked || /true/i.test(acac))) || (acao && acao.toLowerCase()===q.origin.value.toLowerCase() && q.origin.value.toLowerCase()!==location.origin.toLowerCase());
          coAddFinding({url:q.url,method:q.method,origin:q.origin.value,status:res.status,acao,acac,vary,acah,acam,risk});
        },
        onerror:()=>{ coAddFinding({url:q.url,method:q.method,origin:q.origin.value,status:'ERR',acao:'',acac:'',vary:'',acah:'',acam:'',risk:false}); },
        ontimeout:()=>{ coAddFinding({url:q.url,method:q.method,origin:q.origin.value,status:'TIMEOUT',acao:'',acac:'',vary:'',acah:'',acam:'',risk:false}); },
        onloadend:()=>{ co.inFlight--; setTimeout(coPump, CO.DELAY_MS); }
      });
    }
  }
  function coClear(){ co.queue=[]; co.findings.length=0; co.idx=0; co.inFlight=0; coRefs.results.innerHTML=''; coRefs.status.textContent='En espera…'; coUpdateCount(); coPersist(); }
  coRefs.run.onclick=coStart; coRefs.clear.onclick=coClear;
  coRefs.csv.onclick=()=>{ const head=['url','method','origin','status','acao','acac','vary','acah','acam','risk']; csvDownload(`cors_${nowStr()}.csv`, head, co.findings); };

  /* ============================
     Rate-Limit Probe
  ============================ */
  const tabRL = panel.querySelector('#tab_apis_ratelimit');
  const rlTabBtn = panel.querySelector('#tabs_apis .ptk-tab[data-tab="ratelimit"]');
  tabRL.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Rate-Limit Probe</div>
        <div class="ptk-grid">
          <button id="rl_start" class="ptk-btn">Start</button>
          <button id="rl_stop" class="ptk-btn">Stop</button>
          <button id="rl_clear" class="ptk-btn">Clear</button>
          <button id="rl_csv" class="ptk-btn">CSV</button>
          <label>QPS <input type="number" id="rl_qps" value="2" min="1" style="width:60px"></label>
          <label>Dur (s) <input type="number" id="rl_dur" value="5" min="1" style="width:60px"></label>
          <label>Método <select id="rl_method"><option value="HEAD">HEAD</option><option value="GET">GET</option></select></label>
          <label><input type="checkbox" id="rl_safe" checked> Safe Mode</label>
        </div>
      </div>
      <div class="ptk-row"><label>Endpoints<br><textarea id="rl_targets" rows="3" style="width:100%"></textarea></label></div>
      <div id="rl_status" style="margin:6px 0">En espera…</div>
      <div id="rl_results"></div>
    </div>
  `;
  const rlRefs = {
    start: tabRL.querySelector('#rl_start'),
    stop: tabRL.querySelector('#rl_stop'),
    clear: tabRL.querySelector('#rl_clear'),
    csv: tabRL.querySelector('#rl_csv'),
    qps: tabRL.querySelector('#rl_qps'),
    dur: tabRL.querySelector('#rl_dur'),
    method: tabRL.querySelector('#rl_method'),
    safe: tabRL.querySelector('#rl_safe'),
    targets: tabRL.querySelector('#rl_targets'),
    status: tabRL.querySelector('#rl_status'),
    results: tabRL.querySelector('#rl_results')
  };
  const rl = { findings:[], running:false, stop:false };
  try{ if(typeof GM_getValue==='function') rlRefs.targets.value=GM_getValue(`${site}_rl_targets`,''); }catch(_e){}
  rlRefs.targets.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_rl_targets`, rlRefs.targets.value); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') rlRefs.qps.value=GM_getValue(`${site}_rl_qps`,2); }catch(_e){}
  rlRefs.qps.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_rl_qps`, Number(rlRefs.qps.value)||1); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') rlRefs.dur.value=GM_getValue(`${site}_rl_dur`,5); }catch(_e){}
  rlRefs.dur.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_rl_dur`, Number(rlRefs.dur.value)||1); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') rlRefs.method.value=GM_getValue(`${site}_rl_method`,'HEAD'); }catch(_e){}
  rlRefs.method.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_rl_method`, rlRefs.method.value); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') rlRefs.safe.checked=GM_getValue(`${site}_rl_safe`, true); }catch(_e){}
  rlRefs.safe.onchange=()=>{ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_rl_safe`, rlRefs.safe.checked); }catch(_e){} };
  try{ if(typeof GM_getValue==='function') rl.findings=JSON.parse(GM_getValue(`${site}_ratelimit`, '[]'))||[]; }catch(_e){}
  rl.findings.forEach(f=>rlRender(f));
  rlUpdateCount();
  function rlUpdateCount(){ if(rlTabBtn) rlTabBtn.textContent=`Rate-Limit Probe (${rl.findings.length})`; }
  function rlPersist(){ try{ if(typeof GM_setValue==='function') GM_setValue(`${site}_ratelimit`, JSON.stringify(rl.findings)); }catch(_e){} }
  function rlRender(f){ const fam=family(f.first429?429:(f.s5xx?500:(f.s4xx?400:200))); const div=document.createElement('div'); div.className='ptk-row'; div.innerHTML=`<div><b>${f.method}</b> <a class="ptk-link" href="${f.url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${f.url}</a></div><div class="ptk-code" style="color:${famColor(fam)}">2xx=${f.s2xx} 4xx=${f.s4xx} 5xx=${f.s5xx}${f.first429?` · 429#${f.first429}`:''}${f.retryAfter?` · Retry-After:${escHTML(f.retryAfter)}`:''}${f.rateLimit?` · ${escHTML(f.rateLimit)}`:''}</div>`; rlRefs.results.appendChild(div); }
  function rlTargets(){ return unique(rlRefs.targets.value.split(/\s+/).map(s=>s.trim()).filter(Boolean).map(p=>mkAbs(p)).filter(Boolean).filter(u=>!rlRefs.safe.checked||sameOrigin(u))); }
  function rlHandle(r,res,idx){ const status=res.status; if(status>=200&&status<300) r.s2xx++; else if(status>=400&&status<500) r.s4xx++; else if(status>=500) r.s5xx++; const hdr=res.responseHeaders||''; if(r.retryAfter===''){ const m=/^retry-after:\s*([^\n]+)/im.exec(hdr); if(m) r.retryAfter=m[1].trim(); } if(r.rateLimit===''){ const rls=[]; hdr.split(/\r?\n/).forEach(h=>{ if(/^x-ratelimit-/i.test(h)) rls.push(h.trim()); }); if(rls.length) r.rateLimit=rls.join('; '); } if(status===429&&r.first429==null) r.first429=idx+1; }
  async function rlRun(url){ const qps=Math.max(1,Number(rlRefs.qps.value)||1); const dur=Math.max(1,Number(rlRefs.dur.value)||1); const method=rlRefs.method.value; const max=Math.ceil(qps*dur); const delay=1000/qps; const r={url,method,qps,dur,total:0,s2xx:0,s4xx:0,s5xx:0,first429:null,retryAfter:'',rateLimit:''}; for(let i=0;i<max && !rl.stop;i++){ rlRefs.status.textContent=`${method} ${url} ${i+1}/${max}`; await new Promise(res=>{ GM_xmlhttpRequest({method,url,timeout:8000,onload:resp=>{ rlHandle(r,resp,i); res(); },onerror:()=>{res();},ontimeout:()=>{res();}}); }); r.total++; if(i<max-1 && !rl.stop) await new Promise(r2=>setTimeout(r2,delay)); } rl.findings.push(r); rlRender(r); rlPersist(); rlUpdateCount(); }
  async function rlStart(){ if(rl.running) return; const targets=rlTargets(); if(!targets.length){ rlRefs.status.textContent='Sin endpoints'; return; } rl.running=true; rl.stop=false; rl.findings.length=0; rlRefs.results.innerHTML=''; rlPersist(); rlUpdateCount(); for(const u of targets){ if(rl.stop) break; await rlRun(u); } rl.running=false; rlRefs.status.textContent=rl.stop?'Detenido.':`Finalizado. Endpoints: ${targets.length}`; }
  function rlStop(){ rl.stop=true; }
  function rlClear(){ rl.stop=false; rl.running=false; rl.findings.length=0; rlRefs.results.innerHTML=''; rlRefs.status.textContent='En espera…'; rlUpdateCount(); rlPersist(); }
  rlRefs.start.onclick=rlStart; rlRefs.stop.onclick=rlStop; rlRefs.clear.onclick=rlClear; rlRefs.csv.onclick=()=>{ const head=['url','method','qps','duration','total','2xx','4xx','5xx','first429','retryAfter','rateLimit']; csvDownload(`ratelimit_${nowStr()}.csv`, head, rl.findings); };

  /* ============================
     API Fuzzer (sin cambios, CSV con file/line)
  ============================ */
  const tabFuzz = panel.querySelector('#tab_apis_fuzzer');
  const fzTabBtn = panel.querySelector('#tabs_apis .ptk-tab[data-tab="fuzzer"]');
  tabFuzz.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">API Fuzzer</div>
        <div class="ptk-grid">
          <button id="fz_start" class="ptk-btn">Fuzz</button>
          <button id="fz_pause" class="ptk-btn">Pausar</button>
          <button id="fz_clear" class="ptk-btn">Clear</button>
          <button id="fz_csv" class="ptk-btn">CSV</button>
        </div>
      </div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="fz_safe" checked> Safe Mode (GET/HEAD/OPTIONS)</label>
        <label>Métodos:
          <label><input type="checkbox" class="fz_m" data-m="GET" checked> GET</label>
          <label><input type="checkbox" class="fz_m" data-m="OPTIONS" checked> OPTIONS</label>
          <label><input type="checkbox" class="fz_m" data-m="HEAD" checked> HEAD</label>
          <label><input type="checkbox" class="fz_m" data-m="POST"> POST</label>
          <label><input type="checkbox" class="fz_m" data-m="PUT"> PUT</label>
          <label><input type="checkbox" class="fz_m" data-m="DELETE"> DELETE</label>
        </label>
      </div>
      <div class="ptk-grid">
        <label>Seeds extra (coma): <input type="text" id="fz_seeds" placeholder="/api,/api/v3,/admin,/internal,/oauth2"></label>
      </div>
      <div id="fz_status" style="margin:6px 0">En espera…</div>
      <div id="fz_results"></div>
    </div>
  `;
  const fzRefs = {
    start: tabFuzz.querySelector('#fz_start'), pause: tabFuzz.querySelector('#fz_pause'), clear: tabFuzz.querySelector('#fz_clear'),
    csv: tabFuzz.querySelector('#fz_csv'), status: tabFuzz.querySelector('#fz_status'), results: tabFuzz.querySelector('#fz_results'),
    safe: tabFuzz.querySelector('#fz_safe'), seeds: tabFuzz.querySelector('#fz_seeds'), mChecks: tabFuzz.querySelectorAll('.fz_m')
  };
  const pillFzTxt = pill.querySelector('#pill_fuzz_txt'), pillFzBar = pill.querySelector('#pill_fuzz_bar');
  const fz = { started:false, paused:false, inFlight:0, idx:0, queue:[], findings:[], session:0 };

  function fzUpdateCount(){ if (fzTabBtn) fzTabBtn.textContent = `API Fuzzer (${fz.findings.length})`; }

  function fzSeeds(){
    const base = ['', 'api','api/v3','api/v4','v1','v2','auth','oauth','oauth2','users','login','health','status','docs','api-docs','swagger','openapi.json','v3/api-docs','graphql','admin','internal'];
    const extras = (fzRefs.seeds.value||'').split(',').map(s=>s.trim()).filter(Boolean).map(s=>s.replace(/^\/?/,''));
    const fromDOM = [...document.querySelectorAll('a[href], [data-href]')].map(n=>n.getAttribute('href')||n.getAttribute('data-href')||'').filter(v=>/^\/(api|v\d+|auth|graphql|docs|swagger|openapi)/i.test(v)).map(v=>v.replace(/#.*/,''));
    return unique([...base, ...extras, ...fromDOM]).map(s=>'/'+s.replace(/^\/+/,''));
  }
  function fzBuildQueue(){
    const methods = [...fzRefs.mChecks].filter(c=>c.checked).map(c=>c.dataset.m);
    const safe = fzRefs.safe.checked;
    const seeds = fzSeeds();
    const params = ['?q=test','?format=json','?debug=1','?limit=1','?page=1'];
    const Q = [];
    seeds.forEach(s=>{
      const abs = mkAbs(s); if (!abs || !sameOrigin(abs)) return;
      methods.forEach(m=>{
        if (safe && !/^(GET|HEAD|OPTIONS)$/i.test(m)) return;
        Q.push({url:abs, method:m, body:null});
        if (/GET/i.test(m)){ params.forEach(p=>Q.push({url:abs + (abs.includes('?')?'&':p), method:'GET', body:null})); }
        if (!safe && /^(POST|PUT|DELETE)$/i.test(m)){ Q.push({url:abs, method:m, body: JSON.stringify({probe:true, echo:'ptk', ts:Date.now()})}); }
      });
    });
    if (!safe && methods.includes('POST')){
      ['/graphql','/api/graphql','/v1/graphql','/v2/graphql'].forEach(p=>{
        const u = mkAbs(p); if (u && sameOrigin(u)){ Q.push({url:u, method:'POST', body: JSON.stringify({ query: '{__typename}' })}); }
      });
    }
    return Q;
  }
  function fzSetProg(){
    const total = fz.queue.length, done = fz.idx;
    const pct = total ? Math.round(done/total*100) : 0;
    pillFzTxt.textContent = total? `${done}/${total} • activos=${fz.inFlight}${fz.paused?' • PAUSADO':''}` : '—';
    pillFzBar.style.width = pct + '%';
  }
  function fzAddFinding(url,method,status,headers,note){
    fz.findings.push({ url, file:url, line:'', method, status, note: note||'', allow: (headers.match(/^\s*allow:\s*([^\n\r]+)/gim)||[]).join(' | '), wwwAuth:(headers.match(/^\s*www-authenticate:\s*([^\n\r]+)/gim)||[]).join(' | ') });
    fzUpdateCount();
    const fam = family(status);
    const div = document.createElement('div'); div.className='ptk-row';
    div.innerHTML = `<div><b>${method}</b> <a class="ptk-link" href="${url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${url}</a></div>
                     <div class="ptk-code" style="color:${famColor(fam)}">HTTP ${status} ${note?`· ${note}`:''}</div>`;
    fzRefs.results.appendChild(div);
  }
  function fzPump(){
    if (fz.paused) return;
    while (fz.inFlight<FUZZ.MAX_CONCURRENCY && fz.idx<fz.queue.length){
      const {url,method,body} = fz.queue[fz.idx++]; const session=fz.session; fz.inFlight++; fzRefs.status.textContent=`${method} ${url}`; fzSetProg();
      GM_xmlhttpRequest({
        method, url, timeout: FUZZ.TIMEOUT_MS,
        headers: body? {'Content-Type':'application/json','X-Requested-With':'PentestToolkit'} : {'X-Requested-With':'PentestToolkit'},
        data: body || undefined,
        onload: res=>{
          if (session!==fz.session) return;
          let note=''; if (res.status===405) note='Method Not Allowed'; if (res.status===401) note='Unauthorized'; if (res.status===403) note='Forbidden';
          fzAddFinding(url,method,res.status,res.responseHeaders||'',note);
        },
        onloadend: ()=>{ if (session!==fz.session) return; fz.inFlight--; setTimeout(fzPump, FUZZ.DELAY_MS); }
      });
    }
    if (fz.idx>=fz.queue.length && fz.inFlight===0) fzRefs.status.textContent=`Finalizado. Intentos: ${fz.queue.length}`;
  }
  function fzStart(){ if (fz.started) return; fz.started=true; fz.paused=false; fz.session++; fz.idx=0; fz.inFlight=0; fz.findings.length=0; fzRefs.results.innerHTML=''; fzUpdateCount(); fz.queue=fzBuildQueue(); if (!fz.queue.length){ fzRefs.status.textContent='Sin endpoints a probar.'; fz.started=false; return; } fzPump(); }
  function fzPause(){ if (!fz.started) return; fz.paused=!fz.paused; fzRefs.pause.textContent=fz.paused?'Reanudar':'Pausar'; if (!fz.paused) fzPump(); }
  function fzClear(){ fz.paused=true; fz.started=false; fz.session++; fz.idx=0; fz.inFlight=0; fz.queue=[]; fz.findings.length=0; fzRefs.results.innerHTML=''; fzRefs.status.textContent='En espera…'; fzRefs.pause.textContent='Pausar'; fzSetProg(); fzUpdateCount(); }
  fzRefs.start.onclick=fzStart; fzRefs.pause.onclick=fzPause; fzRefs.clear.onclick=fzClear;
  fzRefs.csv.onclick=()=>{ const head=['file','line','method','url','status','note','allow','wwwAuth']; csvDownload(`api_fuzzer_${nowStr()}.csv`, head, fz.findings); };

  /* ============================
     Cloud Buckets (detectar rutas reales + línea, progreso)
  ============================ */
  const tabBucks = panel.querySelector('#tab_buckets');
  tabBucks.innerHTML = `
    <div class="ptk-box">
      <div class="ptk-flex">
        <div class="ptk-hdr">Cloud Buckets (desde rutas detectadas)</div>
        <div class="ptk-grid">
          <button id="bk_scan" class="ptk-btn">Detectar + Probar</button>
          <button id="bk_clear" class="ptk-btn">Clear</button>
          <button id="bk_csv" class="ptk-btn">CSV</button>
        </div>
      </div>
      <div class="ptk-grid">
        <label><input type="checkbox" id="bk_from_dom" checked> Escanear DOM/HTML</label>
        <label><input type="checkbox" id="bk_from_js" checked> Escanear JS externos</label>
        <label><input type="checkbox" id="bk_from_crawl" checked> Usar URLs del Crawler</label>
      </div>
      <div id="bk_status" style="margin:6px 0">En espera…</div>
      <div id="bk_results"></div>
    </div>
  `;
  const bkRefs = {
    scan: tabBucks.querySelector('#bk_scan'), clear: tabBucks.querySelector('#bk_clear'), csv: tabBucks.querySelector('#bk_csv'),
    status: tabBucks.querySelector('#bk_status'), results: tabBucks.querySelector('#bk_results'),
    fromDom: tabBucks.querySelector('#bk_from_dom'), fromJs: tabBucks.querySelector('#bk_from_js'), fromCrawl: tabBucks.querySelector('#bk_from_crawl')
  };
  const pillBkTxt = pill.querySelector('#pill_bk_txt');
  const pillBkBar = pill.querySelector('#pill_bk_bar');

  const bk = { findings:[], candidates:[], candSet:new Set(), resSet:new Set(), session:0, det:{total:0,done:0,active:0}, en:{total:0,done:0} };

  // Regex proveedores
  const RX_S3_VHOST = /https?:\/\/([a-z0-9.\-]+)\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\/[^\s"'<>]*/gi;
  const RX_S3_PATH  = /https?:\/\/s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_GCS_HOST = /https?:\/\/([a-z0-9.\-]+)\.storage\.googleapis\.com\/[^\s"'<>]*/gi;
  const RX_GCS_PATH = /https?:\/\/storage\.googleapis\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_DO_SPACE = /https?:\/\/([a-z0-9.\-]+)\.([a-z0-9-]+)\.digitaloceanspaces\.com\/[^\s"'<>]*/gi;
  const RX_AZURE_BL = /https?:\/\/([a-z0-9-]+)\.blob\.core\.windows\.net\/([a-z0-9\-]+)\/[^\s"'<>]*/gi;
  const RX_AZURE_DFS= /https?:\/\/([a-z0-9-]+)\.dfs\.core\.windows\.net\/([a-z0-9\-]+)\/[^\s"'<>]*/gi;
  const RX_CF_R2   = /https?:\/\/([a-z0-9-]+)\.r2\.cloudflarestorage\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_OSS_VHOST = /https?:\/\/([a-z0-9.\-]+)\.oss-([a-z0-9-]+)\.aliyuncs\.com\/[^\s"'<>]*/gi;
  const RX_OSS_PATH  = /https?:\/\/oss-([a-z0-9-]+)\.aliyuncs\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_WASABI_VHOST = /https?:\/\/([a-z0-9.\-]+)\.s3(?:[\.-]([a-z0-9-]+))?\.wasabisys\.com\/[^\s"'<>]*/gi;
  const RX_WASABI_PATH  = /https?:\/\/s3(?:[\.-]([a-z0-9-]+))?\.wasabisys\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_B2_VHOST = /https?:\/\/([a-z0-9.\-]+)\.s3\.([a-z0-9-]+)\.backblazeb2\.com\/[^\s"'<>]*/gi;
  const RX_B2_PATH  = /https?:\/\/s3\.([a-z0-9-]+)\.backblazeb2\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_B2_NATIVE= /https?:\/\/f[0-9]{3,}\.backblazeb2\.com\/file\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_LINODE_VHOST = /https?:\/\/([a-z0-9.\-]+)\.([a-z0-9-]+)\.linodeobjects\.com\/[^\s"'<>]*/gi;
  const RX_LINODE_PATH  = /https?:\/\/([a-z0-9-]+)\.linodeobjects\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
  const RX_VULTR_VHOST = /https?:\/\/([a-z0-9.\-]+)\.([a-z0-9-]+)\.vultrobjects\.com\/[^\s"'<>]*/gi;
  const RX_VULTR_PATH  = /https?:\/\/([a-z0-9-]+)\.vultrobjects\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;

  function scanTextForBuckets(text, source, srcUrl){
    const out = [];
    function push(m, prov, style, extra){
      const idx = m.index || 0;
      out.push(Object.assign({
        provider: prov, style, url: m[0], source, file: srcUrl||'', line: lineFromIndex(text, idx)-1
      }, extra||{}));
    }
    let m;
    while ((m = RX_S3_VHOST.exec(text))) push(m,'S3','vhost',{bucket:m[1]});
    while ((m = RX_S3_PATH.exec(text)))  push(m,'S3','path',{bucket:m[1]});
    while ((m = RX_GCS_HOST.exec(text))) push(m,'GCS','vhost',{bucket:m[1]});
    while ((m = RX_GCS_PATH.exec(text))) push(m,'GCS','path',{bucket:m[1]});
    while ((m = RX_DO_SPACE.exec(text))) push(m,'DO','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_CF_R2.exec(text))) push(m,'R2','path',{account:m[1],bucket:m[2]});
    while ((m = RX_OSS_VHOST.exec(text))) push(m,'OSS','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_OSS_PATH.exec(text)))  push(m,'OSS','path',{bucket:m[2],region:m[1]});
    while ((m = RX_WASABI_VHOST.exec(text))) push(m,'WASABI','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_WASABI_PATH.exec(text)))  push(m,'WASABI','path',{bucket:m[2],region:m[1]});
    while ((m = RX_B2_VHOST.exec(text)))   push(m,'B2','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_B2_PATH.exec(text)))    push(m,'B2','path',{bucket:m[2],region:m[1]});
    while ((m = RX_B2_NATIVE.exec(text)))  push(m,'B2','native',{bucket:m[1]});
    while ((m = RX_LINODE_VHOST.exec(text))) push(m,'LINODE','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_LINODE_PATH.exec(text)))  push(m,'LINODE','path',{bucket:m[2],region:m[1]});
    while ((m = RX_VULTR_VHOST.exec(text))) push(m,'VULTR','vhost',{bucket:m[1],region:m[2]});
    while ((m = RX_VULTR_PATH.exec(text)))  push(m,'VULTR','path',{bucket:m[2],region:m[1]});
    while ((m = RX_AZURE_BL.exec(text))) push(m,'AZURE','blob',{account:m[1],container:m[2]});
    while ((m = RX_AZURE_DFS.exec(text))) push(m,'AZURE','dfs',{account:m[1],container:m[2]});
    return out;
  }
  async function collectBucketCandidates(){
    bk.candSet.clear();
    const out = [];
    function addC(c){
      const key = JSON.stringify([c.provider,c.style,c.bucket||'',c.account||'',c.container||'',c.region||'',c.file||'',c.line||'']);
      if (bk.candSet.has(key)) return;
      bk.candSet.add(key); out.push(c);
    }
    // DOM+HTML
    if (bkRefs.fromDom.checked){
      const html = document.documentElement.outerHTML || '';
      scanTextForBuckets(html, 'DOM', location.href).forEach(addC);
      // atributos rápidos (sin línea)
      document.querySelectorAll('[src],[href],[data],[action]').forEach(n=>{
        ['src','href','data','action'].forEach(a=>{
          const v = n.getAttribute && n.getAttribute(a); if (!v) return;
          scanTextForBuckets(v, 'DOM-attr', location.href).forEach(c=>{ c.line=''; addC(c); });
        });
      });
    }
    // JS externos: usar assets del crawler + scripts de la página
    const doJS = bkRefs.fromJs.checked;
    if (!doJS) return Promise.resolve(out);
    const jsUrls = new Set();
    [...document.scripts].forEach(s=>{ if (s.src) jsUrls.add(s.src); });
    if (bkRefs.fromCrawl.checked) unique(cr.assets).forEach(u=>jsUrls.add(u));
    const arr = unique([...jsUrls]).filter(u=>/\.js(\?|#|$)/i.test(u));
    bk.det.total = arr.length; bk.det.done=0; bk.det.active=0; bkSetProg('detect');

    async function fetchJS(u){
      bk.det.active++; bkSetProg('detect');
      return new Promise(resolve=>{
        GM_xmlhttpRequest({
          method:'GET', url:u, timeout:BUCKS.TIMEOUT_MS,
          onload: res=>{ const text = res.responseText||''; scanTextForBuckets(text, 'JS', u).forEach(addC); },
          onloadend: ()=>{ bk.det.active--; bk.det.done++; bkSetProg('detect'); resolve(); },
          onerror: ()=>{ bk.det.active--; bk.det.done++; bkSetProg('detect'); resolve(); },
          ontimeout: ()=>{ bk.det.active--; bk.det.done++; bkSetProg('detect'); resolve(); }
        });
      });
    }

    for (let i=0;i<arr.length;i+=BUCKS.JS_DETECT_MAX_CONC){
      const slice = arr.slice(i, i+BUCKS.JS_DETECT_MAX_CONC);
      await Promise.all(slice.map(fetchJS));
    }
    return out;
  }
  function bucketListingURL(c){
    if (c.provider==='S3'){
      if (c.style==='vhost') return `https://${c.bucket}.s3.amazonaws.com/?list-type=2`;
      if (c.style==='path')  return `https://s3.amazonaws.com/${c.bucket}?list-type=2`;
    } else if (c.provider==='GCS'){
      return `https://storage.googleapis.com/storage/v1/b/${c.bucket}/o?maxResults=10`;
    } else if (c.provider==='DO'){
      if (c.region) return `https://${c.bucket}.${c.region}.digitaloceanspaces.com/?list-type=2`;
      return null;
    } else if (c.provider==='R2'){
      if (c.account && c.bucket) return `https://${c.account}.r2.cloudflarestorage.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='OSS'){
      if (!c.region || !c.bucket) return null;
      if (c.style==='vhost') return `https://${c.bucket}.oss-${c.region}.aliyuncs.com/?list-type=2`;
      if (c.style==='path')  return `https://oss-${c.region}.aliyuncs.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='WASABI'){
      const r = c.region ? `.${c.region}` : '';
      if (c.style==='vhost') return `https://${c.bucket}.s3${r}.wasabisys.com/?list-type=2`;
      if (c.style==='path')  return `https://s3${r}.wasabisys.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='B2'){
      if (!c.region || !c.bucket) return null;
      if (c.style==='vhost') return `https://${c.bucket}.s3.${c.region}.backblazeb2.com/?list-type=2`;
      if (c.style==='path')  return `https://s3.${c.region}.backblazeb2.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='LINODE'){
      if (!c.region || !c.bucket) return null;
      if (c.style==='vhost') return `https://${c.bucket}.${c.region}.linodeobjects.com/?list-type=2`;
      if (c.style==='path')  return `https://${c.region}.linodeobjects.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='VULTR'){
      if (!c.region || !c.bucket) return null;
      if (c.style==='vhost') return `https://${c.bucket}.${c.region}.vultrobjects.com/?list-type=2`;
      if (c.style==='path')  return `https://${c.region}.vultrobjects.com/${c.bucket}?list-type=2`;
      return null;
    } else if (c.provider==='AZURE'){
      if (c.style==='blob' || c.style==='dfs'){
        if (c.container) return `https://${c.account}.blob.core.windows.net/${c.container}?restype=container&comp=list`;
        return `https://${c.account}.blob.core.windows.net/?comp=list`;
      }
    }
    return null;
  }
  function bkSetProg(stage){
    // stage: 'detect' o 'enum'
    if (stage==='detect'){
      const total = bk.det.total, done = bk.det.done;
      const pct = total ? Math.round(done/total*100) : 0;
      pillBkTxt.textContent = total ? `Detección JS ${done}/${total} • activos=${bk.det.active}` : (bk.en.total? `Enum ${bk.en.done}/${bk.en.total}` : '—');
      pillBkBar.style.width = pct + '%';
    } else {
      const total = bk.en.total, done = bk.en.done;
      const pct = total ? Math.round(done/total*100) : 0;
      pillBkTxt.textContent = `Enum ${done}/${total}`;
      pillBkBar.style.width = pct + '%';
    }
  }
  function bkAdd(url, status, note, meta){
    const key = url; if (bk.resSet.has(key)) return; bk.resSet.add(key);
    const fam = family(status);
    const rec = Object.assign({ url, status, note: note||'' }, meta||{});
    bk.findings.push(rec);
    const div = document.createElement('div'); div.className='ptk-row';
    const infoTop = `${rec.provider||''}${rec.bucket?` · ${rec.bucket}`:''}${rec.account?` · ${rec.account}`:''}${rec.container?` · ${rec.container}`:''}${rec.region?` · ${rec.region}`:''}`;
    const src = `${rec.file||''}${(typeof rec.line==='number' && rec.line>=0)?` :${rec.line+1}`:''}`;
    div.innerHTML = `<div><a class="ptk-link" href="${url}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${url}</a></div>
                     <div class="ptk-code" style="color:${famColor(fam)}">${infoTop} ${note?`· ${note}`:''}</div>
                     <div class="ptk-code" style="opacity:.85">${src}</div>`;
    bkRefs.results.appendChild(div);
  }
  function testURL(u, cb){ GM_xmlhttpRequest({ method:'GET', url:u, timeout: BUCKS.TIMEOUT_MS, onload:r=>cb(r.status, r.responseText||'', r.responseHeaders||''), onerror:()=>cb(0,'',''), ontimeout:()=>cb(0,'','') }); }

  async function bkScan(){
    bk.session++; bk.findings.length=0; bk.candidates.length=0; bk.resSet.clear(); bk.candSet.clear();
    bkRefs.results.innerHTML='';
    bkRefs.status.textContent='Recolectando rutas reales de buckets…';
    bk.det.total = bk.det.done = bk.det.active = 0; bk.en.total = bk.en.done = 0; bkSetProg('detect');

    const cands = await collectBucketCandidates();
    bk.candidates = cands;
    if (!cands.length){ bkRefs.status.textContent='No se detectaron rutas a buckets en DOM/JS.'; pillBkTxt.textContent='—'; pillBkBar.style.width='0%'; return; }

    bkRefs.status.textContent = `Candidatos: ${cands.length} · probando enumeración…`;
    bk.en.total = cands.length; bk.en.done = 0; bkSetProg('enum');

    let i=0;
    (function pump(){
      if (i>=cands.length){ bkRefs.status.textContent = `Listo. Detectados: ${cands.length}`; bkSetProg('enum'); return; }
      const c = cands[i++]; const lurl = bucketListingURL(c);
      const info = { provider:c.provider, bucket:c.bucket||'', account:c.account||'', container:c.container||'', region:c.region||'', file:c.file||'', line: (typeof c.line==='number'?c.line: '') };
      if (!lurl){ bkAdd(c.url, 0, 'No se pudo derivar URL de listado', info); bk.en.done++; bkSetProg('enum'); setTimeout(pump, 40); return; }
      bkRefs.status.textContent = `Probar: ${lurl}`;
      testURL(lurl, (code, body)=>{
        let note='';
        if (/ListBucketResult/i.test(body) || /<EnumerationResults/i.test(body) || /"items":\s*\[/i.test(body)) { note='LISTING OK (posible público)'; }
        else if (code===403){ note='Forbidden (existe, no listable)'; }
        else if (code===404){ note='No existe'; }
        bkAdd(lurl, code, note, info);
        bk.en.done++; bkSetProg('enum');
        setTimeout(pump, 60);
      });
    })();
  }
  bkRefs.scan.onclick=bkScan;
  bkRefs.clear.onclick=()=>{ bk.findings.length=0; bk.candidates.length=0; bk.resSet.clear(); bk.candSet.clear(); bkRefs.results.innerHTML=''; bkRefs.status.textContent='En espera…'; pillBkTxt.textContent='—'; pillBkBar.style.width='0%'; };
    bkRefs.csv.onclick=()=>{ const head=['provider','bucket','account','container','region','file','line','url','status','note']; csvDownload(`buckets_${nowStr()}.csv`, head, bk.findings.map(x=>({provider:x.provider||'',bucket:x.bucket||'',account:x.account||'',container:x.container||'',region:x.region||'',file:x.file||'',line:(typeof x.line==='number'?(x.line+1):''),url:x.url,status:x.status,note:x.note}))); };

    /* ============================
       Hardening Checks
    ============================ */
    const tabHard = panel.querySelector('#tab_hard');
    tabHard.innerHTML = `
      <div class="ptk-box">
        <div class="ptk-flex">
          <div class="ptk-hdr">Misconfigs & Hardening</div>
          <div class="ptk-grid">
            <button id="hd_run" class="ptk-btn">Check</button>
            <button id="hd_clear" class="ptk-btn">Clear</button>
          </div>
        </div>
        <div id="hd_results"></div>
      </div>`;
    const hdRefs = { results: tabHard.querySelector('#hd_results') };
    function hdAuditCookies(){
      return new Promise(resolve=>{
        const list = document.cookie ? document.cookie.split(/;\s*/) : [];
        GM_xmlhttpRequest({
          method:'GET', url: location.href, headers:{'Cache-Control':'no-cache'},
          onload: res=>{
            const hdrs = res.responseHeaders || '';
            const setCookies = hdrs.match(/^set-cookie:[^\n]+/gim) || [];
            const parsed = setCookies.map(line=>{
              const m = /^set-cookie:\s*([^=]+)=.*$/i.exec(line);
              const attrs = line.split(':').slice(1).join(':');
              return { name:m?m[1].trim():'' , attrs };
            });
            const out = list.map(c=>{
              const name = c.split('=')[0];
              const sc = parsed.find(p=>p.name===name);
              const info = { name, secure:false, sameSite:null, prefix:null, longExpiry:false };
              info.prefix = name.startsWith('__Host-')?'__Host-':name.startsWith('__Secure-')?'__Secure-':null;
              if (sc){
                info.secure = /;\s*secure/i.test(sc.attrs);
                const sm = /;\s*samesite=([^;]+)/i.exec(sc.attrs);
                info.sameSite = sm?sm[1]:null;
                const em = /;\s*expires=([^;]+)/i.exec(sc.attrs);
                if (em){
                  const d = new Date(em[1]);
                  if (d - Date.now() > 1000*60*60*24*365) info.longExpiry = true;
                }
              }
              return info;
            });
            resolve(out);
          },
          onerror: _=> resolve(list.map(c=>({ name:c.split('=')[0] })))
        });
      });
    }
    function hdCheckHeaders(){
      return new Promise(resolve=>{
        GM_xmlhttpRequest({
          method:'GET', url: location.href, headers:{'Cache-Control':'no-cache'},
          onload: res=>{
            const hdrs = res.responseHeaders || '';
            const has = h=>new RegExp('^'+h+':','im').test(hdrs);
            resolve({
              csp: has('content-security-policy'),
              xfo: has('x-frame-options'),
              hsts: has('strict-transport-security'),
              corp: has('cross-origin-resource-policy'),
              coop: has('cross-origin-opener-policy'),
              coep: has('cross-origin-embedder-policy')
            });
          },
          onerror: _=> resolve(null)
        });
      });
    }
    function hdCheckSRI(){
      const miss = [];
      document.querySelectorAll('script[src]').forEach(s=>{ if(!s.integrity) miss.push(s.src); });
      return miss;
    }
    function hdTestCORS(){
      return new Promise(resolve=>{
        const evil = 'https://evil.example';
        GM_xmlhttpRequest({
          method:'OPTIONS', url: location.href,
          headers:{
            'Origin': evil,
            'Access-Control-Request-Method':'POST',
            'Access-Control-Request-Headers':'X-Test'
          },
          onload: res=>{
            const hdrs = res.responseHeaders || '';
            const grab = n=>{ const m = new RegExp('^'+n+':\s*([^\n]+)','im').exec(hdrs); return m?m[1].trim():null; };
            resolve({
              allowOrigin: grab('access-control-allow-origin'),
              allowCreds: /access-control-allow-credentials:\s*true/i.test(hdrs),
              allowHeaders: grab('access-control-allow-headers'),
              allowMethods: grab('access-control-allow-methods')
            });
          },
          onerror: _=> resolve(null)
        });
      });
    }
    function hdTestClick(){
      return new Promise(resolve=>{
        const iframe = document.createElement('iframe');
        iframe.style.position='absolute';
        iframe.style.left='-9999px';
        iframe.src = location.href + (location.href.includes('?')?'&':'?')+'tr_iframe='+Date.now();
        iframe.onload=()=>{
          let ok=false;
          try{ ok = iframe.contentWindow.location.href !== 'about:blank'; }
          catch(e){ ok=false; }
          iframe.remove();
          resolve(ok);
        };
        document.body.appendChild(iframe);
        setTimeout(()=>{ try{iframe.remove();}catch(_e){}; resolve(false); },8000);
      });
    }
    tabHard.querySelector('#hd_run').addEventListener('click', async ()=>{
      hdRefs.results.innerHTML='<div class="ptk-row">Checking…</div>';
      const [cookies, headers, cors, frameOk] = await Promise.all([
        hdAuditCookies(), hdCheckHeaders(), hdTestCORS(), hdTestClick()
      ]);
      const sri = hdCheckSRI();
      const res = hdRefs.results; res.innerHTML='';
      const cDiv = document.createElement('div');
      cDiv.className='ptk-row';
      if (cookies && cookies.length){
        cDiv.innerHTML='<div class="ptk-hdr">Cookies</div><ul>'+cookies.map(c=>{
          const warns=[];
          if (!c.secure) warns.push('Secure');
          if (!c.sameSite) warns.push('SameSite');
          if (!c.prefix) warns.push('prefix');
          if (c.longExpiry) warns.push('long-exp');
          return `<li>${escHTML(c.name)}${warns.length?': '+warns.join(' | '):' OK'}</li>`;
        }).join('')+'</ul>';
      } else cDiv.innerHTML='<div class="ptk-hdr">Cookies</div><div>Ninguna</div>';
      res.appendChild(cDiv);
      const hDiv=document.createElement('div');
      hDiv.className='ptk-row';
      hDiv.innerHTML=`<div class="ptk-hdr">Headers</div>
        <div>CSP: ${headers&&headers.csp?'OK':'MISSING'}</div>
        <div>XFO: ${headers&&headers.xfo?'OK':'MISSING'}</div>
        <div>HSTS: ${headers&&headers.hsts?'OK':'MISSING'}</div>
        <div>CORP: ${headers&&headers.corp?'OK':'MISSING'}</div>
        <div>COOP: ${headers&&headers.coop?'OK':'MISSING'}</div>
        <div>COEP: ${headers&&headers.coep?'OK':'MISSING'}</div>`;
      res.appendChild(hDiv);
      const sDiv=document.createElement('div');
      sDiv.className='ptk-row';
      sDiv.innerHTML='<div class="ptk-hdr">SRI</div>'+(sri.length?`<ul>${sri.map(s=>`<li>${escHTML(s)}</li>`).join('')}</ul>`:'<div>All scripts have integrity</div>');
      res.appendChild(sDiv);
      const coDiv=document.createElement('div');
      coDiv.className='ptk-row';
      coDiv.innerHTML='<div class="ptk-hdr">CORS</div>'+(cors?`<div>ACAO=${escHTML(cors.allowOrigin||'n/a')} ACAC=${cors.allowCreds} A C A H=${escHTML(cors.allowHeaders||'')} A C A M=${escHTML(cors.allowMethods||'')}</div>`:'<div>Error</div>');
      res.appendChild(coDiv);
      const cjDiv=document.createElement('div');
      cjDiv.className='ptk-row';
      cjDiv.innerHTML=`<div class="ptk-hdr">Clickjacking</div><div>${frameOk?'Framable':'Blocked'}</div>`;
      res.appendChild(cjDiv);
    });
    tabHard.querySelector('#hd_clear').addEventListener('click',()=>{ hdRefs.results.innerHTML=''; });

    /* ============================
       AUTOSTARTS (opcionales)
    ============================ */
    if (FILES.AUTO_START) setTimeout(()=>tabFiles.querySelector('#sf_start').click(), 700);
    if (JS.AUTO_START) setTimeout(()=>tabJS.querySelector('#js_start').click(), 900);

  if (typeof window !== 'undefined'){
    window.addEventListener('error', e => {
      if(e.error && e.error.__trLogged) return;
      logError(e.error || e.message);
    });
    window.addEventListener('unhandledrejection', e => {
      if(e.reason && e.reason.__trLogged) return;
      logError(e.reason);
    });
  }

})();

/* ==============================================
   CaptureCore: unified hooking & export
   Hooks fetch, XHR, WebSocket, EventSource,
   postMessage, BroadcastChannel and ServiceWorkers.
   Provides exporters to HAR/JSON/CSV/Markdown and
   simple domain filtering.
=============================================== */
(function(global){
  const records = [];
  let domainFilter = null;
  const dangerPatterns = [
    /\b[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\b/,
    /\b(?:token|jwt|bearer|secret|key)\b/i,
    /https?:\/\/[^\s'\"]+/i
  ];
  function shouldLog(url){
    if (!url) return false;
    if (!domainFilter) return true;
    try{
      const u = new URL(url, location.href);
      return u.hostname.endsWith(domainFilter);
    }catch(_e){ return false; }
  }
  function push(rec){
    if (rec.url && !shouldLog(rec.url)) return;
    records.push(rec);
  }
  function headersToObj(headers){
    const obj={};
    if (headers){
      if (typeof headers.forEach==='function'){
        headers.forEach((v,k)=>obj[k]=v);
      }else if (Array.isArray(headers)){
        headers.forEach(([k,v])=>obj[k]=v);
      }else{
        Object.entries(headers).forEach(([k,v])=>obj[k]=v);
      }
    }
    return obj;
  }

  const origFetch = global.fetch;
  if (typeof origFetch === 'function'){
    global.fetch = async function(input, init){
      const url = (typeof input === 'string') ? input : (input && input.url) || '';
      const method = (init && init.method) || (input && input.method) || 'GET';
      const reqHdrs = headersToObj((init && init.headers) || (input && input.headers));
      const reqBody = (init && init.body) || '';
      const start = performance.now();
      const res = await origFetch.apply(this, arguments);
      const end = performance.now();
      const clone = res.clone();
      const resHdrs = headersToObj(clone.headers);
      const text = await clone.text().catch(()=> '');
      push({
        type:'fetch',
        url, method,
        request:{ headers:reqHdrs, body:reqBody },
        response:{ status:res.status, headers:resHdrs, body:text, size:text.length },
        time:end-start
      });
      return res;
    };
  }

  const origXHROpen = XMLHttpRequest.prototype.open;
  const origXHRSend = XMLHttpRequest.prototype.send;
  const origXHRSetHdr = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function(method, url){
    this._tr_method = method;
    this._tr_url = url;
    this._tr_headers = {};
    return origXHROpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function(k,v){
    this._tr_headers[k]=v;
    return origXHRSetHdr.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body){
    const start = performance.now();
    this.addEventListener('loadend', ()=>{
      const end = performance.now();
      try{
        push({
          type:'xhr',
          url:this._tr_url,
          method:this._tr_method,
          request:{ headers:this._tr_headers, body:body || '' },
          response:{ status:this.status, headers:parseHeaders(this.getAllResponseHeaders()), body:this.responseText, size:(this.responseText||'').length },
          time:end-start
        });
      }catch(e){ logError(e); }
    });
    return origXHRSend.apply(this, arguments);
  };
  function parseHeaders(str){
    const out={};
    (str||'').trim().split(/\r?\n/).forEach(line=>{
      const i=line.indexOf(':');
      if(i>0) out[line.slice(0,i).trim().toLowerCase()]=line.slice(i+1).trim();
    });
    return out;
  }

  const OrigWS = global.WebSocket;
  if (typeof OrigWS === 'function'){
    global.WebSocket = function(...args){
      const ws = new OrigWS(...args);
      const url = args[0];
      push({ type:'ws.connect', url });
      const origSend = ws.send;
      ws.send = function(data){
        push({ type:'ws.send', url, data:String(data) });
        return origSend.apply(this, arguments);
      };
      ws.addEventListener('message', ev=>{
        push({ type:'ws.recv', url, data:String(ev.data) });
      });
      return ws;
    };
  }

  const OrigES = global.EventSource;
  if (typeof OrigES === 'function'){
    global.EventSource = function(...args){
      const es = new OrigES(...args);
      const url = args[0];
      push({ type:'es.connect', url });
      es.addEventListener('message', ev=>{
        push({ type:'es.message', url, data:String(ev.data) });
      });
      return es;
    };
  }

  (function(){
    const origPM = global.postMessage;
    if (typeof origPM === 'function'){
      global.postMessage = function(msg, targetOrigin, transfer){
        detect('postMessage.send', msg, { target: targetOrigin });
        return origPM.apply(this, arguments);
      };
      global.addEventListener('message', ev=>{
        detect('postMessage.receive', ev.data, { origin: ev.origin });
      });
    }
  })();

  (function(){
    const OrigBC = global.BroadcastChannel;
    if (typeof OrigBC === 'function'){
      global.BroadcastChannel = function(name){
        const bc = new OrigBC(name);
        bc.addEventListener('message', ev=>{
          detect('broadcast.receive', ev.data, { channel: name });
        });
        const origPost = bc.postMessage;
        bc.postMessage = function(data){
          detect('broadcast.send', data, { channel: name });
          return origPost.apply(this, arguments);
        };
        return bc;
      };
    }
  })();

  function detect(type, data, extra){
    try{
      const str = typeof data === 'string' ? data : JSON.stringify(data);
      const matches = dangerPatterns.filter(rx=>rx.test(str)).map(rx=>rx.source);
      push(Object.assign({ type, data:str, matches }, extra||{}));
    }catch(e){ logError(e); }
  }

  async function scanServiceWorkers(){
    if (!('serviceWorker' in navigator)) return;
    try{
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const reg of regs){
        const url = reg.active && reg.active.scriptURL;
        let text = '';
        if (url){
          try{ text = await fetch(url).then(r=>r.text()); }catch(_e){}
        }
        const hasCachePut = /cache\.put|caches\.open/gi.test(text);
        push({ type:'serviceWorker', url, hasCachePut, size:text.length });
      }
    }catch(e){ logError(e); }
  }
  scanServiceWorkers();

  function exportJSON(){
    return JSON.stringify(getRecords(), null, 2);
  }
  function exportCSV(){
    const rows = getRecords().map(r=>[
      r.type, r.method||'', r.url||'', r.response && r.response.status || '', r.time||'', r.response && r.response.size || ''
    ].map(v=>`"${String(v).replace(/"/g,'""')}"`).join(','));
    rows.unshift('type,method,url,status,time,size');
    return rows.join('\n');
  }
  function exportMarkdown(){
    const rows = getRecords().map(r=>`|${r.type}|${r.method||''}|${r.url||''}|${r.response&&r.response.status||''}|${r.time||''}|${r.response&&r.response.size||''}|`);
    rows.unshift('|type|method|url|status|time|size|','|---|---|---|---|---|---|');
    return rows.join('\n');
  }
  function exportHAR(){
    const entries = getRecords().filter(r=>r.type==='fetch'||r.type==='xhr').map(r=>({
      startedDateTime:new Date().toISOString(),
      time:r.time||0,
      request:{
        method:r.method,
        url:r.url,
        headers:objToHarArr(r.request && r.request.headers),
        bodySize:(r.request && r.request.body && r.request.body.length)||0,
        postData:{ text:r.request && r.request.body || '' }
      },
      response:{
        status:r.response && r.response.status || 0,
        statusText:'',
        headers:objToHarArr(r.response && r.response.headers),
        content:{ size:r.response && r.response.size || 0, text:r.response && r.response.body || '' }
      }
    }));
    return JSON.stringify({ log:{ version:'1.2', creator:{ name:'TamperRecon' }, entries } }, null, 2);
  }
  function objToHarArr(obj){
    const arr=[];
    obj = obj||{};
    Object.keys(obj).forEach(k=>arr.push({name:k, value:obj[k]}));
    return arr;
  }
  function getRecords(){
    if (!domainFilter) return records.slice();
    return records.filter(r=>{
      if (!r.url) return false;
      try{ return new URL(r.url, location.href).hostname.endsWith(domainFilter); }catch(_e){ return false; }
    });
  }
  function setDomainFilter(domain){ domainFilter = domain || null; }

  global.TRCore = { records, exportJSON, exportCSV, exportMarkdown, exportHAR, setDomainFilter };
})(typeof window !== 'undefined' ? window : globalThis);

/* ============================
   RECONNAISSANCE HELPERS
============================ */
(function(global){
  'use strict';
  const SOURCE_MAP_EXT = '.map';
  async function discoverSourceMap(scriptUrl, fetcher){
    const out = { names:new Set(), sources:new Set() };
    try{
      fetcher = fetcher || (u=>fetch(u).then(r=>r.ok?r.text():''));
      const mapUrl = scriptUrl + SOURCE_MAP_EXT;
      const mapText = await fetcher(mapUrl);
      const map = JSON.parse(mapText);
      if (Array.isArray(map.names)) map.names.forEach(n=>n && out.names.add(n));
      if (Array.isArray(map.sources)) map.sources.forEach(p=>p && out.sources.add(p));
    }catch(_e){/* ignore */}
    return out;
  }
  function mineParams(text){
    const params = new Set();
    if (!text) return params;
    const urlRx = /[?&]([a-zA-Z0-9_\-]+)=/g; let m;
    while((m=urlRx.exec(text))) params.add(m[1]);
    const attrRx = /name=["']?([a-zA-Z0-9_\-:]+)/g;
    while((m=attrRx.exec(text))) params.add(m[1]);
    const jsRx = /[\{,]\s*([a-zA-Z0-9_\-]+)\s*:/g;
    while((m=jsRx.exec(text))) params.add(m[1]);
    return params;
  }
  function detectSPARoutes(js){
    const routes = new Set();
    if (!js) return routes;
    const pathRx = /path\s*:\s*['"]([^'"?#]+)['"]/g;
    const whenRx = /\.when\(\s*['"]([^'"?#]+)['"]/g; let m;
    while((m=pathRx.exec(js))) routes.add(m[1]);
    while((m=whenRx.exec(js))) routes.add(m[1]);
    return routes;
  }
  function virtualCrawl(base, routes){
    const out=[]; if (!base) return out; routes = routes || [];
    for(const r of routes){
      try{ const u=new URL(r, base).href; out.push(u); }
      catch(_e){/* ignore */}
    }
    return out;
  }
  global.TRRecon = { discoverSourceMap, mineParams, detectSPARoutes, virtualCrawl };
})(typeof window !== 'undefined' ? window : globalThis);

/* ============================
   RUNTIME MONITORING ADD-ONS
============================ */
(function(global){
  'use strict';

  const activity = [];
  function logActivity(type, detail){
    const entry = { type, detail, time: Date.now() };
    activity.push(entry);
    try{ addConsoleLog('log', ['[TR]', type, detail]); }catch(_e){}
  }

  // fetch
  if (global.fetch){
    const origFetch = global.fetch;
    global.fetch = async function(...args){
      const input = args[0]; const init = args[1] || {};
      const method = (init && init.method) || (input && input.method) || 'GET';
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const start = Date.now();
      const reqHeaders = ebHeadersToObj(init.headers || (input && input.headers));
      const reqBody = init && init.body;
      TREventBus.emit({ type:'net:fetch', phase:'start', method, url, status:0, ok:false, ms:0, reqHeaders, resHeaders:{}, reqBody:ebPreview(reqBody), resBody:'', ts:start });
      logActivity('fetch', String(args[0]));
      try{
        const res = await origFetch.apply(this, args);
        let resHeaders = {};
        try{ res.headers.forEach((v,k)=>resHeaders[k]=v); }catch(_e){}
        let resBody = '';
        try{ resBody = await res.clone().text(); }catch(_e){}
        const ms = Date.now() - start;
        TREventBus.emit({ type:'net:fetch', phase:'end', method, url, status:res.status, ok:res.ok, ms, reqHeaders, resHeaders, reqBody:ebPreview(reqBody), resBody:ebPreview(resBody), ts:Date.now() });
        logActivity('fetch-response', res.url || '');
        return res;
      }catch(e){
        const ms = Date.now() - start;
        TREventBus.emit({ type:'net:fetch', phase:'error', method, url, status:0, ok:false, ms, reqHeaders, resHeaders:{}, reqBody:ebPreview(reqBody), resBody:String(e), ts:Date.now() });
        logActivity('fetch-error', e && e.message || '');
        throw e;
      }
    };
  }

  // XMLHttpRequest
  if (global.XMLHttpRequest){
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){
      this.__tr_url = url; this.__tr_method = method; this.__tr_start = Date.now();
      TREventBus.emit({ type:'net:xhr', phase:'start', method, url, status:0, ok:false, ms:0, reqHeaders:{}, resHeaders:{}, reqBody:'', resBody:'', ts:this.__tr_start });
      logActivity('xhr-open', method + ' ' + url);
      return origOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(body){
      this.__tr_body = body;
      const xhr = this;
      xhr.addEventListener('loadend', function(){
        const ms = Date.now() - (xhr.__tr_start || Date.now());
        const resHeaders = ebParseHeaders(xhr.getAllResponseHeaders ? xhr.getAllResponseHeaders() : '');
        TREventBus.emit({ type:'net:xhr', phase:'end', method:xhr.__tr_method || '', url:xhr.__tr_url || '', status:xhr.status, ok:(xhr.status>=200 && xhr.status<300), ms, reqHeaders:{}, resHeaders, reqBody:ebPreview(xhr.__tr_body), resBody:ebPreview(xhr.response), ts:Date.now() });
      });
      logActivity('xhr-send', this.__tr_url || '');
      return origSend.call(this, body);
    };
  }

  // WebSocket
  if (global.WebSocket){
    const OrigWebSocket = global.WebSocket;
    global.WebSocket = function(url, protocols){
      const ws = new OrigWebSocket(url, protocols);
      ws.__tr_url = url;
      TREventBus.emit({ type:'ws:open', url, data:undefined, ts:Date.now() });
      logActivity('websocket', url);
      const origSend = ws.send;
      ws.send = function(data){
        TREventBus.emit({ type:'ws:send', url:ws.__tr_url, data:ebPreview(data), ts:Date.now() });
        return origSend.call(ws, data);
      };
      ws.addEventListener('message', ev=>{
        TREventBus.emit({ type:'ws:message', url:ws.__tr_url, data:ebPreview(ev.data), ts:Date.now() });
        logActivity('ws-message', ev.data);
      });
      ws.addEventListener('close', ev=>{
        TREventBus.emit({ type:'ws:close', url:ws.__tr_url, code:ev.code, reason:ev.reason, ts:Date.now() });
      });
      return ws;
    };
  }

  // EventSource
  if (global.EventSource){
    const OrigEventSource = global.EventSource;
    global.EventSource = function(url, opts){
      const es = new OrigEventSource(url, opts);
      logActivity('eventsource', url);
      es.addEventListener('message', ev=>{
        TREventBus.emit({ type:'sse:message', url, event:ev.type, data:ebPreview(ev.data), ts:Date.now() });
        logActivity('es-message', ev.data);
      });
      return es;
    };
  }

  // postMessage
  if (global.postMessage){
    const origPostMessage = global.postMessage;
    global.postMessage = function(msg, target, transfer){
      try{
        TREventBus.emit({ type:'pm:post', origin:(location && location.origin)||'', target:String(target), size:ebSize(msg), data:ebPreview(msg), ts:Date.now() });
      }catch(_e){}
      try{ logActivity('postMessage', JSON.stringify(msg)); }catch(_e){ logActivity('postMessage','[unserializable]'); }
      return origPostMessage.call(this, msg, target, transfer);
    };
    if (global.addEventListener){
      global.addEventListener('message', ev=>{
        try{ TREventBus.emit({ type:'pm:message', origin:ev.origin, target:(location && location.origin)||'', size:ebSize(ev.data), data:ebPreview(ev.data), ts:Date.now() }); }catch(_e){}
      });
    }
  }

  // BroadcastChannel
  if (global.BroadcastChannel){
    const OrigBC = global.BroadcastChannel;
    global.BroadcastChannel = function(name){
      logActivity('broadcastchannel', name);
      const bc = new OrigBC(name);
      TREventBus.emit({ type:'pm:bc-open', channel:name, origin:(location && location.origin)||'', target:name, size:0, data:null, ts:Date.now() });
      const origBCPost = bc.postMessage;
      bc.postMessage = function(msg){
        try{ TREventBus.emit({ type:'pm:bc-post', channel:name, origin:(location && location.origin)||'', target:name, size:ebSize(msg), data:ebPreview(msg), ts:Date.now() }); }catch(_e){}
        try{ logActivity('broadcast-post', JSON.stringify(msg)); }catch(_e){ logActivity('broadcast-post','[unserializable]'); }
        return origBCPost.call(bc, msg);
      };
      bc.addEventListener('message', ev=>{
        try{ TREventBus.emit({ type:'pm:bc-msg', channel:name, origin:name, target:(location && location.origin)||'', size:ebSize(ev.data), data:ebPreview(ev.data), ts:Date.now() }); }catch(_e){}
        try{ logActivity('broadcast-msg', JSON.stringify(ev.data)); }catch(_e){ logActivity('broadcast-msg','[unserializable]'); }
      });
      return bc;
    };
  }

  // Service Workers
  if (global.navigator && global.navigator.serviceWorker){
    global.navigator.serviceWorker.getRegistrations().then(regs=>{
      regs.forEach(reg=>logActivity('serviceWorker', reg.active && reg.active.scriptURL || ''));
    }).catch(e=>logActivity('sw-error', e && e.message || ''));
  }

  // atob
  if (global.atob){
    const origAtob = global.atob;
    global.atob = function(str){
      logActivity('atob', str);
      const out = origAtob.call(this, str);
      const ts = Date.now();
      addCodecLog({ codec:'atob', input:str, output:out, length:out.length, isJSON:ebIsJSON(out), isJWT:ebIsJWT(str), ts, inputPreview:ebPreview(str,100), outputPreview:ebPreview(out,100), inputFull:ebToString(str), outputFull:ebToString(out) });
      TREventBus.emit({ type:'codec:atob', inputPreview:ebPreview(str,100), outputPreview:ebPreview(out,100), length:out.length, isJSON:ebIsJSON(out), isJWT:ebIsJWT(str), ts });
      return out;
    };
  }

  // btoa
  if (global.btoa){
    const origBtoa = global.btoa;
    global.btoa = function(str){
      logActivity('btoa', str);
      const out = origBtoa.call(this, str);
      if (codecCfg.btoa){
        const ts = Date.now();
        addCodecLog({ codec:'btoa', input:str, output:out, length:out.length, isJSON:ebIsJSON(str), isJWT:ebIsJWT(str), ts, inputPreview:ebPreview(str,100), outputPreview:ebPreview(out,100), inputFull:ebToString(str), outputFull:ebToString(out) });
        TREventBus.emit({ type:'codec:btoa', inputPreview:ebPreview(str,100), outputPreview:ebPreview(out,100), length:out.length, isJSON:ebIsJSON(str), isJWT:ebIsJWT(str), ts });
      }
      return out;
    };
  }

  // TextDecoder
  if (global.TextDecoder){
    const OrigTD = global.TextDecoder;
    global.TextDecoder = function(...args){
      const td = new OrigTD(...args);
      const origDecode = td.decode;
      td.decode = function(...dargs){
        const res = origDecode.apply(td, dargs);
        logActivity('textdecoder', res);
        if (codecCfg.text){
          const ts = Date.now();
          addCodecLog({ codec:'textdecoder', input:dargs[0], output:res, length:res.length||0, isJSON:ebIsJSON(res), isJWT:ebIsJWT(res), ts, inputPreview:ebPreview(dargs[0],100), outputPreview:ebPreview(res,100), inputFull:ebToString(dargs[0]), outputFull:ebToString(res) });
          TREventBus.emit({ type:'codec:decode', inputPreview:ebPreview(dargs[0],100), outputPreview:ebPreview(res,100), length:res.length||0, isJSON:ebIsJSON(res), isJWT:ebIsJWT(res), ts });
        }
        return res;
      };
      return td;
    };
  }

  // TextEncoder
  if (global.TextEncoder){
    const OrigTE = global.TextEncoder;
    global.TextEncoder = function(...args){
      const te = new OrigTE(...args);
      const origEncode = te.encode;
      te.encode = function(...eargs){
        const res = origEncode.apply(te, eargs);
        logActivity('textencoder', eargs[0]);
        if (codecCfg.text){
          const ts = Date.now();
          addCodecLog({ codec:'textencoder', input:eargs[0], output:res, length:res.length||0, isJSON:ebIsJSON(eargs[0]), isJWT:ebIsJWT(eargs[0]), ts, inputPreview:ebPreview(eargs[0],100), outputPreview:ebPreview(res,100), inputFull:ebToString(eargs[0]), outputFull:ebToString(res) });
          TREventBus.emit({ type:'codec:encode', inputPreview:ebPreview(eargs[0],100), outputPreview:ebPreview(res,100), length:res.length||0, isJSON:ebIsJSON(eargs[0]), isJWT:ebIsJWT(eargs[0]), ts });
        }
        return res;
      };
      return te;
    };
  }

  // crypto.subtle
  if (global.crypto && global.crypto.subtle){
    const s = global.crypto.subtle;
    ['encrypt','decrypt','digest'].forEach(op=>{
      if (typeof s[op] === 'function'){
        const orig = s[op].bind(s);
        s[op] = async function(...args){
          const alg = args[0];
          const res = await orig(...args);
          let len = res && (res.byteLength || res.length) || 0;
          let sample = '';
          let iv = '';
          try{ sample = ebPreview(new Uint8Array(res).slice(0,16)); }catch(_e){}
          try{ if(alg && alg.iv) iv = ebPreview(new Uint8Array(alg.iv).slice(0,16)); }catch(_e){}
          try{ TREventBus.emit({ type:`crypto:${op}`, alg: (alg && alg.name)||String(alg), ivPreview:redact(iv), length: len, sample:redact(sample), ts:Date.now() }); }catch(_e){}
          return res;
        };
      }
    });
    if (s.exportKey){
      const origExportKey = s.exportKey.bind(s);
      s.exportKey = async function(format, key){
        const res = await origExportKey(format, key);
        let len = res && (res.byteLength || res.length) || 0;
        try{ TREventBus.emit({ type:'crypto:exportKey', alg:format, length:len, sample:redact(ebPreview(res,80)), ts:Date.now() }); }catch(_e){}
        logActivity('exportKey', format);
        return res;
      };
    }
  }

  // storage & JWT
  function analyzeJWT(token){
    try{
      const parts = token.split('.');
      if (parts.length >= 2){
        const h = JSON.parse(global.atob(parts[0]));
        const p = JSON.parse(global.atob(parts[1]));
        logActivity('jwt', JSON.stringify({ header:h, payload:p }));
      }
    }catch(e){ logActivity('jwt-error', e && e.message || ''); }
  }
  function inspectStore(storeName){
    try{
      const s = global[storeName];
      if (!s) return;
      for(let i=0;i<s.length;i++){
        const k = s.key(i); const v = s.getItem(k);
        if(/token|key|secret|email/i.test(v||'')) logActivity(storeName, k + '=' + v);
        if(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v||'')) analyzeJWT(v);
      }
    }catch(e){ logActivity('storage-error', e && e.message || ''); }
  }
  inspectStore('localStorage');
  inspectStore('sessionStorage');

  // simple open redirect fuzzer
  function openRedirectFuzzer(url){
    try{
      const params = ['next','url','redirect','returnTo'];
      const u = new URL(url || global.location.href, global.location.href);
      params.forEach(p=>{
        if(u.searchParams.has(p)) logActivity('open-redirect', p + '=' + u.searchParams.get(p));
      });
    }catch(e){ logActivity('open-redirect-error', e && e.message || ''); }
  }
  openRedirectFuzzer();

  global.TRMonitor = { logActivity, activity, openRedirectFuzzer };
})(typeof window !== 'undefined' ? window : globalThis);

if (typeof module !== 'undefined' && module.exports){
  module.exports = { TRCore: globalThis.TRCore, TRRecon: globalThis.TRRecon, TRMonitor: globalThis.TRMonitor, TREventBus: globalThis.TREventBus, TREventBuffers: globalThis.TREventBuffers };
}
