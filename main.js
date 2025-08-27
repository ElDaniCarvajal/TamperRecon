const consoleLogs = [];
let renderConsole = () => {};
function addConsoleLog(level, args){
  const msg = args.map(a => {
    try { return typeof a === 'string' ? a : JSON.stringify(a); }
    catch(_e){ return String(a); }
  }).join(' ');
  consoleLogs.push({ time: new Date().toISOString(), level, message: msg });
  try { renderConsole(); } catch(_e){}
}
(function(){
  ['log','error','warn'].forEach(level=>{
    globalThis.console[level] = (...args)=>addConsoleLog(level, args);
  });
})();

/* Simple EventBus for runtime monitoring */
const EventBus = (function(){
  let subs = [];
  let nextId = 1;
  function emit(evt){
    evt = evt || {}; evt.ts = evt.ts || Date.now();
    subs.forEach(s=>{ try{ if(!s.filter || s.filter(evt)) s.handler(evt); }catch(_e){} });
  }
  function subscribe(filter, handler){
    const id = nextId++;
    subs.push({id, filter, handler});
    return id;
  }
  function unsubscribe(id){ subs = subs.filter(s=>s.id!==id); }
  return {emit, subscribe, unsubscribe};
})();

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
  function saveJSON(filename, obj){
    const blob = new Blob([JSON.stringify(obj,null,2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download=filename; a.click(); URL.revokeObjectURL(url);
  }
  function truncateBytes(data, max=4096){
    try{
      if (typeof data === 'string') return data.length>max ? data.slice(0,max)+'…' : data;
      if (data && data.byteLength){
        return data.byteLength>max ? data.slice(0,max) : data;
      }
    }catch(_e){}
    return data;
  }
  function redact(str, opts){
    str = String(str||''); opts = opts || {}; const h = opts.head||32; const t = opts.tail||32;
    if (str.length <= h+t+1) return str;
    return str.slice(0,h)+'…'+str.slice(-t);
  }
  function createStore(limit=2000){
    const items = [];
    return {
      push(ev){ if(items.length>=limit) items.shift(); items.push(ev); },
      get(){ return items; },
      clear(){ items.length = 0; }
    };
  }
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
    runtimeLogs.push(rec);
    logEvent('runtime', rec);
    updateRuntimeBadge();
    if (typeof rsRender === 'function') rsRender();
    if (typeof runtimeNotify === 'function') runtimeNotify();
  }
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
      <div class="ptk-tabs" id="tabs">
        <div class="ptk-tab active" data-tab="files">Files</div>
        <div class="ptk-tab" data-tab="js">JS Hunter</div>
        <div class="ptk-tab" data-tab="runtime">Runtime Secrets</div>
        <div class="ptk-tab" data-tab="crawler">Crawler</div>
        <div class="ptk-tab" data-tab="versions">Versions</div>
        <div class="ptk-tab" data-tab="fuzzer">API Fuzzer</div>
        <div class="ptk-tab" data-tab="buckets">Cloud Buckets</div>
        <div class="ptk-tab" data-tab="hard">Hardening</div>
        <div class="ptk-tab" data-tab="console">Console</div>
        <div class="ptk-tab" data-tab="errors">Errors</div>
      </div>
      <section id="tab_files"></section>
      <section id="tab_js" style="display:none"></section>
      <section id="tab_runtime" style="display:none"></section>
      <section id="tab_crawler" style="display:none"></section>
      <section id="tab_versions" style="display:none"></section>
      <section id="tab_fuzzer" style="display:none"></section>
      <section id="tab_buckets" style="display:none"></section>
      <section id="tab_hard" style="display:none"></section>
      <section id="tab_console" style="display:none"></section>
      <section id="tab_errors" style="display:none"></section>
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
  const tabsEl = panel.querySelector('#tabs');
  const runtimeTabBtn = tabsEl.querySelector('.ptk-tab[data-tab="runtime"]');
  const consoleTabBtn = tabsEl.querySelector('.ptk-tab[data-tab="console"]');
  const errorsTabBtn = tabsEl.querySelector('.ptk-tab[data-tab="errors"]');
  updateRuntimeBadge = function(){
    if (runtimeTabBtn) runtimeTabBtn.textContent = `Runtime Secrets (${runtimeLogs.length})`;
  };
  function updateConsoleBadge(){
    if (consoleTabBtn) consoleTabBtn.textContent = `Console (${consoleLogs.length})`;
  }
  function updateErrorBadge(){
    if (errorsTabBtn) errorsTabBtn.textContent = `Errors (${errorLog.length})`;
  }
  updateRuntimeBadge();
  updateConsoleBadge();
  updateErrorBadge();
  function showTab(name){
      ['files','js','runtime','crawler','versions','fuzzer','buckets','hard','console','errors'].forEach(t=>{
      panel.querySelector('#tab_'+t).style.display = (t===name)?'':'none';
      const tabBtn = tabsEl.querySelector(`.ptk-tab[data-tab="${t}"]`);
      if (tabBtn) tabBtn.classList.toggle('active', t===name);
    });
  }
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
  runtimeNotify = function(){
    showTab('runtime');
    if (!runtimeAlerted){
      runtimeAlerted = true;
      try{ addConsoleLog('log', ['Runtime secret found']); }catch(e){ logError(e); }
    }
  };
  tabsEl.addEventListener('click', (e)=>{
    const t = e.target && e.target.closest('.ptk-tab');
    if (!t) return;
    showTab(t.dataset.tab);
  });

  /* ============================
     FILES (igual que antes, con CSV file/line)
  ============================ */
  const tabFiles = panel.querySelector('#tab_files');
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
    sf.findings.length=0; tabElsF.results.innerHTML='';
    sf.queue = sfBuildQueue(); sf.idx=0; sf.inFlight=0; sf.done=0;
    if (!sf.queue.length){ tabElsF.status.textContent='Sin rutas para probar.'; sfSetProgress(0,0); sf.started=false; return; }
    sfUpdateStatus(); sfPump();
  }
  function sfPauseResume(){ if (!sf.started) return; sf.paused=!sf.paused; tabElsF.pause.textContent = sf.paused?'Reanudar':'Pausar'; sfUpdateStatus(); if (!sf.paused) sfPump(); }
  function sfClear(){ sf.paused=true; sf.started=false; sf.session++; sf.queue=[]; sf.inFlight=0; sf.idx=0; sf.done=0; sf.findings.length=0; tabElsF.results.innerHTML=''; tabElsF.status.textContent='En espera…'; sfSetProgress(0,0); tabElsF.pause.textContent='Pausar'; }
  tabElsF.start.onclick=sfStart; tabElsF.pause.onclick=sfPauseResume; tabElsF.clear.onclick=sfClear;
  tabElsF.copy.onclick=()=>{ const current=sf.findings.filter(f=>f.session===sf.session); const out=JSON.stringify(current,null,2); clip(out); tabElsF.copy.textContent='¡Copiado!'; setTimeout(()=>tabElsF.copy.textContent='Copiar JSON',1200); };
  tabElsF.csv.onclick=()=>{ const rows=sf.findings.filter(f=>f.session===sf.session); const head=['file','line','url','status','note','family']; csvDownload(`files_probe_${nowStr()}.csv`, head, rows); };

/* ============================
   JS Secret & Endpoint Hunter (dominios solo en strings/comentarios; scope; anti-ruido en minificados)
============================ */
const tabJS = panel.querySelector('#tab_js');
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
      logEvent('network', { method:'fetch', url });
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
        logEvent('network', { method:'xhr', url });
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
  jh.findings.length=0; jsRefs.results.innerHTML='';
  jh.targets = jsCollectTargets(); jh.queueIdx=0; jh.active=0;
  if (!jh.targets.length){ jsRefs.status.textContent='Sin scripts para analizar.'; jsSetProgress(0,0); jh.started=false; return; }
  jsUpdateStatus(); jsPump();
}
function jsPauseResume(){ if (!jh.started) return; jh.paused=!jh.paused; jsRefs.pause.textContent=jh.paused?'Reanudar JS':'Pausar JS'; jsUpdateStatus(); if (!jh.paused) jsPump(); }
function jsClear(){ jh.paused=true; jh.started=false; jh.session++; jh.targets=[]; jh.queueIdx=0; jh.active=0; jh.findings.length=0; jh.domainsSet.clear(); jsRefs.results.innerHTML=''; jsRefs.status.textContent='En espera…'; jsSetProgress(0,0); jsRefs.pause.textContent='Pausar JS'; }

jsRefs.start.onclick=jsStart; jsRefs.pause.onclick=jsPauseResume; jsRefs.clear.onclick=jsClear;
jsRefs.copy.onclick=()=>{ const current=jh.findings.filter(f=>f.session===jh.session); const out=JSON.stringify(current,null,2); clip(out); jsRefs.copy.textContent='¡Copiado!'; setTimeout(()=>jsRefs.copy.textContent='Copiar JSON',1200); };
jsRefs.csv.onclick=()=>{ const rows=jh.findings.filter(f=>f.session===jh.session).map(r=>({file:r.file,line: (typeof r.line==='number'?(r.line+1):''),type:r.type,value:r.value,host:r.host||''})); const head=['file','line','type','value','host']; csvDownload(`js_hunter_${nowStr()}.csv`, head, rows); };

/* ============================
   Runtime
============================ */
const tabRuntime = panel.querySelector('#tab_runtime');
tabRuntime.innerHTML = `
  <div class="ptk-tabs" id="rt_tabs">
    <div class="ptk-tab active" data-rt="network">Network</div>
    <div class="ptk-tab" data-rt="secrets">Secrets</div>
  </div>
  <section id="rt_network"></section>
  <section id="rt_secrets" style="display:none"></section>
`;
const rtTabsEl = tabRuntime.querySelector('#rt_tabs');
const rtSections = {
  network: tabRuntime.querySelector('#rt_network'),
  secrets: tabRuntime.querySelector('#rt_secrets')
};
rtTabsEl.addEventListener('click', e=>{
  const t = e.target.closest('.ptk-tab'); if(!t) return;
  ['network','secrets'].forEach(n=>{
    rtSections[n].style.display = n===t.dataset.rt?'' : 'none';
    rtTabsEl.querySelector(`.ptk-tab[data-rt="${n}"]`).classList.toggle('active', n===t.dataset.rt);
  });
});

// existing Runtime Secrets moved to sub-section
rtSections.secrets.innerHTML = `
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

// Network sub-tab
rtSections.network.innerHTML = `
  <div class="ptk-box">
    <div class="ptk-flex">
      <div class="ptk-hdr">Network</div>
      <div class="ptk-grid">
        <button id="net_pause" class="ptk-btn">Pausar</button>
        <button id="net_clear" class="ptk-btn">Clear</button>
        <button id="net_json" class="ptk-btn">Export JSON</button>
        <button id="net_csv" class="ptk-btn">Export CSV</button>
      </div>
    </div>
    <div id="net_results"></div>
  </div>
`;
const netStore = createStore(2000);
let netPaused = false;
const netRefs = {
  pause: rtSections.network.querySelector('#net_pause'),
  clear: rtSections.network.querySelector('#net_clear'),
  json:  rtSections.network.querySelector('#net_json'),
  csv:   rtSections.network.querySelector('#net_csv'),
  results: rtSections.network.querySelector('#net_results')
};
function netRender(){
  netRefs.results.innerHTML = '';
  netStore.get().forEach((ev,i)=>{
    const div = document.createElement('div'); div.className='ptk-row';
    const url = ev.url || '';
    const top = document.createElement('div'); top.style.opacity='.8';
    top.textContent = `${i+1} • ${ev.type}`;
    const code = document.createElement('code'); code.className='ptk-code'; code.style.whiteSpace='pre-wrap';
    const txt = `${ev.method||''} ${url}\nstatus: ${ev.status} ms:${ev.ms}`;
    code.textContent = txt;
    div.appendChild(top); div.appendChild(code);
    netRefs.results.appendChild(div);
  });
}
netRefs.pause.onclick=()=>{ netPaused=!netPaused; netRefs.pause.textContent=netPaused?'Reanudar':'Pausar'; };
netRefs.clear.onclick=()=>{ netStore.clear(); netRender(); };
netRefs.json.onclick=()=>{ saveJSON(`network_${nowStr()}.json`, netStore.get()); };
netRefs.csv.onclick=()=>{
  const head=['ts','type','method','url','status','ms'];
  const rows = netStore.get().map(e=>({ts:e.ts,type:e.type,method:e.method||'',url:e.url||'',status:e.status||'',ms:e.ms||''}));
  csvDownload(`network_${nowStr()}.csv`, head, rows);
};
EventBus.subscribe(ev=>/^(net:|ws:|sse:)/.test(ev.type||''), ev=>{
  if(netPaused) return;
  netStore.push(ev);
  netRender();
});
const rsRefs = {
  clear: rtSections.secrets.querySelector('#rs_clear'),
  copy:  rtSections.secrets.querySelector('#rs_copy'),
  dl:    rtSections.secrets.querySelector('#rs_dl'),
  pmToggle: rtSections.secrets.querySelector('#rs_pm_toggle'),
  results: rtSections.secrets.querySelector('#rs_results')
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
rsRefs.clear.onclick=()=>{ runtimeLogs.length=0; rsRender(); };
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
  const tabCrawler = panel.querySelector('#tab_crawler');
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
  function crRenderRow(u, status, ctype, title, note){
    const fam = family(status);
    const div = document.createElement('div'); div.className='ptk-row';
    const t = title ? ` · <b>${title}</b>` : '';
    const n = note ? ` · ${note}` : '';
    div.innerHTML = `<div><a class="ptk-link" href="${u}" target="_blank" rel="noopener noreferrer" style="color:${famColor(fam)}">${u}</a></div>
                     <div class="ptk-code" style="color:${famColor(fam)}">HTTP ${status} · ${ctype||'—'}${t}${n}</div>`;
    crRefs.results.appendChild(div);
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
    crawlEnqueue(location.href);
    ['/robots.txt','/sitemap.xml','/security.txt','/ads.txt'].forEach(p=>crawlEnqueue(location.origin+p));
    crRefs.status.textContent = 'Iniciando…'; crPump();
  }
  function crPause(){ if (!cr.started) return; cr.paused = !cr.paused; crRefs.pause.textContent = cr.paused?'Reanudar':'Pausar'; if (!cr.paused) crPump(); }
  function crClear(){ cr.paused=true; cr.started=false; cr.session++; cr.inFlight=0; cr.q.length=0; cr.pages.length=0; cr.assets.length=0; cr.seen.clear(); crRefs.results.innerHTML=''; crRefs.status.textContent='En espera…'; crRefs.pause.textContent='Pausar'; crSetProgress(); }
  crRefs.start.onclick=crStart; crRefs.pause.onclick=crPause; crRefs.clear.onclick=crClear;
  crRefs.copy.onclick=()=>{ const out=JSON.stringify({pages:cr.pages, assets:unique(cr.assets)}, null, 2); clip(out); crRefs.copy.textContent='¡Copiado!'; setTimeout(()=>crRefs.copy.textContent='Copiar JSON',1200); };
  crRefs.csv.onclick=()=>{ const head=['file','line','url','status','contentType','title','note']; csvDownload(`crawl_pages_${nowStr()}.csv`, head, cr.pages.map(p=>({file:p.file,line:p.line,url:p.url,status:p.status,contentType:p.contentType,title:p.title||'',note:p.note||''}))); };

   /* ============================
     VERSIONS (cola única, anti-stall; headers 1x/host; externos solo si referenciados)
  ============================ */
  const tabVers = panel.querySelector('#tab_versions');
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

  const RX_VER = /\b(?:v|version[^\w]?|ver[^\w]?|release[^\w]?|build[^\w]?){0,1}\s*([0-9]+\.[0-9]+(?:\.[0-9]+){0,3}(?:[-_a-z0-9.]+)?)\b/gi;
  const RX_FILE_VER = /(?:jquery|react|vue|angular|bootstrap|moment|lodash|underscore|d3|leaflet|three|ckeditor|tinymce|swiper|alpine|next|nuxt|webpack|tailwind|fontawesome|sentry|amplitude|mixpanel|express|nestjs|chart|semantic|ember)[^\/]*?([0-9]+(?:\.[0-9]+){1,3})/i;

  function vdAdd(kind, tech, version, url, where, evidence, file, line){
    // Para headers dedup por host, no por URL específica
    const keyUrl = (where==='headers@host') ? (new URL(url)).host : url;
    const key = [kind,tech,version,keyUrl,where,String(line||'')].join('|');
    if (vd.seen.has(key)) return;
    vd.seen.add(key);
    vd.findings.push({ kind, tech, version, url, where, evidence, file: file||url, line: (typeof line==='number' ? (line+1) : '') });
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
  };
  vdRefs.csv.onclick = ()=>{
    const head=['kind','tech','version','file','line','url','where','evidence'];
    csvDownload(`versions_${nowStr()}.csv`, head, vd.findings);
  };

  function vdRun(){
    vd.session++; const mySession = vd.session;
    vd.findings.length=0; vd.seen.clear();
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
     API Fuzzer (sin cambios, CSV con file/line)
  ============================ */
  const tabFuzz = panel.querySelector('#tab_fuzzer');
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
  function fzStart(){ if (fz.started) return; fz.started=true; fz.paused=false; fz.session++; fz.idx=0; fz.inFlight=0; fz.findings.length=0; fzRefs.results.innerHTML=''; fz.queue=fzBuildQueue(); if (!fz.queue.length){ fzRefs.status.textContent='Sin endpoints a probar.'; fz.started=false; return; } fzPump(); }
  function fzPause(){ if (!fz.started) return; fz.paused=!fz.paused; fzRefs.pause.textContent=fz.paused?'Reanudar':'Pausar'; if (!fz.paused) fzPump(); }
  function fzClear(){ fz.paused=true; fz.started=false; fz.session++; fz.idx=0; fz.inFlight=0; fz.queue=[]; fz.findings.length=0; fzRefs.results.innerHTML=''; fzRefs.status.textContent='En espera…'; fzRefs.pause.textContent='Pausar'; fzSetProg(); }
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
      logError(e.error || e.message);
    });
    window.addEventListener('unhandledrejection', e => {
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
      const input = args[0];
      const init = args[1] || {};
      const url = typeof input==='string'?input:(input&&input.url)||'';
      const method = (init.method || (input&&input.method) || 'GET').toUpperCase();
      const start = performance.now();
      try{
        const res = await origFetch.apply(this, args);
        const ms = performance.now()-start;
        EventBus.emit({type:'net:fetch', method, url, status:res.status, ok:res.ok, ms});
        logActivity('fetch', url);
        return res;
      }catch(e){
        const ms = performance.now()-start;
        EventBus.emit({type:'net:fetch', method, url, status:0, ok:false, ms});
        logActivity('fetch-error', url);
        throw e;
      }
    };
  }

  // XMLHttpRequest
  if (global.XMLHttpRequest){
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){
      this.__tr_url = url; this.__tr_method = method;
      return origOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function(body){
      const start = performance.now();
      this.addEventListener('loadend', ()=>{
        const ms = performance.now()-start;
        EventBus.emit({type:'net:xhr', method:this.__tr_method, url:this.__tr_url, status:this.status, ok:this.status>=200&&this.status<400, ms});
      });
      return origSend.call(this, body);
    };
  }

  // WebSocket
  if (global.WebSocket){
    const OrigWebSocket = global.WebSocket;
    global.WebSocket = function(url, protocols){
      const ws = new OrigWebSocket(url, protocols);
      EventBus.emit({type:'ws:open', url});
      const origSend = ws.send;
      ws.send = function(data){
        EventBus.emit({type:'ws:send', url, data:truncateBytes(String(data))});
        return origSend.apply(this, arguments);
      };
      ws.addEventListener('message', ev=>EventBus.emit({type:'ws:message', url, data:truncateBytes(String(ev.data))}));
      ws.addEventListener('close', ev=>EventBus.emit({type:'ws:close', url, code:ev.code, reason:ev.reason}));
      return ws;
    };
  }

  // EventSource
  if (global.EventSource){
    const OrigEventSource = global.EventSource;
    global.EventSource = function(url, opts){
      const es = new OrigEventSource(url, opts);
      EventBus.emit({type:'sse:open', url});
      es.addEventListener('message', ev=>EventBus.emit({type:'sse:message', url, event:ev.type, data:truncateBytes(String(ev.data))}));
      return es;
    };
  }

  // postMessage
  if (global.postMessage){
    const origPostMessage = global.postMessage;
    global.postMessage = function(msg, target, transfer){
      if (capturePostMessage){
        try{ EventBus.emit({type:'pm:postMessage', data:truncateBytes(JSON.stringify(msg)), target}); }catch(_e){ EventBus.emit({type:'pm:postMessage', data:'[unserializable]', target}); }
      }
      return origPostMessage.call(this, msg, target, transfer);
    };
  }

  // BroadcastChannel
  if (global.BroadcastChannel){
    const OrigBC = global.BroadcastChannel;
    global.BroadcastChannel = function(name){
      const bc = new OrigBC(name);
      EventBus.emit({type:'pm:broadcast', channel:name, data:'[open]'});
      const origBCPost = bc.postMessage;
      bc.postMessage = function(msg){
        if (capturePostMessage){
          try{ EventBus.emit({type:'pm:broadcast', channel:name, data:truncateBytes(JSON.stringify(msg))}); }catch(_e){ EventBus.emit({type:'pm:broadcast', channel:name, data:'[unserializable]'}); }
        }
        return origBCPost.call(bc, msg);
      };
      bc.addEventListener('message', ev=>{ if(capturePostMessage){ try{ EventBus.emit({type:'pm:broadcast', channel:name, data:truncateBytes(JSON.stringify(ev.data))}); }catch(_e){ EventBus.emit({type:'pm:broadcast', channel:name, data:'[unserializable]'}); } } });
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
      return origAtob.call(this, str);
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
        return res;
      };
      return td;
    };
  }

  // crypto.subtle.exportKey
  if (global.crypto && global.crypto.subtle && global.crypto.subtle.exportKey){
    const origExportKey = global.crypto.subtle.exportKey.bind(global.crypto.subtle);
    global.crypto.subtle.exportKey = async function(format, key){
      const res = await origExportKey(format, key);
      logActivity('exportKey', format);
      return res;
    };
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
  module.exports = { TRCore: globalThis.TRCore, TRRecon: globalThis.TRRecon, TRMonitor: globalThis.TRMonitor };
}
