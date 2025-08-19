const assert = require('assert');

const logs = [];
function addRuntimeLog(type, code){
  logs.push({type, code});
}

const origEval = global.eval;
global.eval = function(str){
  if (typeof str === 'string') addRuntimeLog('eval', str);
  return origEval(str);
};

const origFunction = global.Function;
global.Function = new Proxy(origFunction, {
  apply(target, thisArg, args){
    const body = args.length && typeof args[args.length-1]==='string' ? args.join(',') : '';
    if (body) addRuntimeLog('Function', body);
    return Reflect.apply(target, thisArg, args);
  },
  construct(target, args){
    const body = args.length && typeof args[args.length-1]==='string' ? args.join(',') : '';
    if (body) addRuntimeLog('Function', body);
    return Reflect.construct(target, args);
  }
});

const origSetTimeout = global.setTimeout;
global.setTimeout = function(handler, timeout, ...args){
  if (typeof handler === 'string') addRuntimeLog('setTimeout', handler);
  return origSetTimeout(handler, timeout, ...args);
};

// Trigger

eval('1+1');
new Function('x','return x*2')(3);
try { setTimeout('console.log(42)',0); } catch {}
setTimeout(()=>{},0);

assert.deepStrictEqual(logs[0], {type:'eval', code:'1+1'});
assert.strictEqual(logs[1].type, 'Function');
assert.ok(logs[1].code.includes('return x*2'));
assert.deepStrictEqual(logs[2], {type:'setTimeout', code:'console.log(42)'});
assert.strictEqual(logs.length,3);

console.log('Runtime proxy tests passed');

// === Scan globals and localStorage ===

const logs2 = [];
function addRuntimeLog2(rec){
  logs2.push(rec);
}

const PATTERNS = [
  { rx:/(api[_-]?key|token|secret|password)/i },
  { rx:/^[0-9a-f]{32}(?:[0-9a-f]{32})?$/i }
];

function matchesSecret(str){
  if (typeof str !== 'string') return false;
  for (const p of PATTERNS){
    p.rx.lastIndex = 0;
    if (p.rx.test(str)) return true;
  }
  return false;
}

function scanGlobals(){
  const seen = new WeakSet();
  const nameRx = /(data|token|secret|pass|key|cfg|config)/i;
  const hexToStr = h=>{
    try{
      if (h.length%2 || /[^0-9a-f]/i.test(h)) return null;
      let out='';
      for(let i=0;i<h.length;i+=2){
        const code=parseInt(h.slice(i,i+2),16);
        if (isNaN(code)) return null;
        out += String.fromCharCode(code);
      }
      return out;
    }catch(_e){ return null; }
  };
  function walk(obj, path){
    if (typeof obj === 'string'){
      if (matchesSecret(obj) || matchesSecret(path)) addRuntimeLog2({ type:'global', key:path, data:obj });
      const decoded = hexToStr(obj);
      if (decoded){
        let parsed=false;
        try{ const js=JSON.parse(decoded); parsed=true; walk(js, path); }catch(_e){}
        if (!parsed && matchesSecret(decoded)) addRuntimeLog2({ type:'global', key:path, data:decoded });
      }
      return;
    }
    if (obj && typeof obj === 'object'){
      if (seen.has(obj)) return; seen.add(obj);
      Object.entries(obj).forEach(([k,v])=>walk(v, path?path+'.'+k:k));
    }
  }
  Object.getOwnPropertyNames(global).forEach(name=>{
    if (!nameRx.test(name)) return;
    walk(global[name], name);
  });
}

function scanLocalStorage(){
  if (!global.localStorage) return;
  for (let i=0; i<global.localStorage.length; i++){
    const k = global.localStorage.key(i);
    const v = global.localStorage.getItem(k);
    if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog2({ type:'localStorage', key:k, data:v });
  }
}

function scanSessionStorage(){
  if (!global.sessionStorage) return;
  for (let i=0; i<global.sessionStorage.length; i++){
    const k = global.sessionStorage.key(i);
    const v = global.sessionStorage.getItem(k);
    if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog2({ type:'sessionStorage', key:k, data:v });
  }
}

function scanCookies(){
  if (!global.document || !global.document.cookie) return;
  const all = global.document.cookie.split(';');
  all.forEach(c => {
    if (!c) return;
    const idx = c.indexOf('=');
    const k = idx>=0 ? c.slice(0,idx).trim() : c.trim();
    const v = idx>=0 ? decodeURIComponent(c.slice(idx+1)) : '';
    if (matchesSecret(v) || matchesSecret(k)) addRuntimeLog2({ type:'cookie', key:k, data:v });
  });
}

const AC_DATA_ARR = [
  "315949337a426b6338234924417661614d24356c5737576a24362121232a4d65",
  "52443840443623644152623437716c33",
  "7b22757365726e616d65223a2022736572766963696f732e6d6f76696c40696e742e636f7070656c2e636f6d222c227573657270617373776f7264223a202261637475616c697a6163696f6e222c227573657274797065223a20317d",
  "c1ef74068b0653252b981e6c0cd35e49fbc2df55b765900e5e85c4e8571f528b",
  "96e5fbd355ed852a5834e8"
];
global.AC_DATA = { foo:{ token:'abc123' }, other:'none', arr: AC_DATA_ARR };
global.localStorage = {
  _data:{ apiKey:'token-XYZ', other:'value' },
  length: 2,
  key(i){ return Object.keys(this._data)[i]; },
  getItem(k){ return this._data[k]; }
};
global.sessionStorage = {
  _data:{ sessionToken:'abc-session', other:'v' },
  length: 2,
  key(i){ return Object.keys(this._data)[i]; },
  getItem(k){ return this._data[k]; }
};
global.document = { cookie:'apiKey=secret123; other=val' };

scanGlobals();
scanLocalStorage();
scanSessionStorage();
scanCookies();

assert.deepStrictEqual(logs2[0], { type:'global', key:'AC_DATA.foo.token', data:'abc123' });
assert.deepStrictEqual(logs2[1], { type:'global', key:'AC_DATA.arr.0', data:AC_DATA_ARR[0] });
assert.deepStrictEqual(logs2[2], { type:'global', key:'AC_DATA.arr.1', data:AC_DATA_ARR[1] });
assert.deepStrictEqual(logs2[3], { type:'global', key:'AC_DATA.arr.2.userpassword', data:'actualizacion' });
assert.deepStrictEqual(logs2[4], { type:'global', key:'AC_DATA.arr.3', data:AC_DATA_ARR[3] });
assert.deepStrictEqual(logs2[5], { type:'localStorage', key:'apiKey', data:'token-XYZ' });
assert.deepStrictEqual(logs2[6], { type:'sessionStorage', key:'sessionToken', data:'abc-session' });
assert.deepStrictEqual(logs2[7], { type:'cookie', key:'apiKey', data:'secret123' });
assert.strictEqual(logs2.length,8);

console.log('Runtime scan tests passed');

// === WebSocket, EventSource and postMessage hooks ===

const logs3 = [];
function addRuntimeLog3(rec){
  logs3.push(rec);
}

// Stubs
class FakeWS {
  constructor(url){ this.url=url; this.listeners={}; }
  send(data){}
  addEventListener(ev, cb){ this.listeners[ev]=cb; }
  dispatch(ev, data){ if (this.listeners[ev]) this.listeners[ev]({ data }); }
}
global.WebSocket = function(url){ return new FakeWS(url); };

class FakeES {
  constructor(url){ this.url=url; this.listeners={}; }
  addEventListener(ev, cb){ this.listeners[ev]=cb; }
  dispatch(ev, data){ if (this.listeners[ev]) this.listeners[ev]({ data }); }
}
global.EventSource = function(url){ return new FakeES(url); };

let msgHandler;
global.addEventListener = function(ev, cb){ if (ev==='message') msgHandler = cb; };
global.postMessage = function(msg, origin){ if (msgHandler) msgHandler({ data: msg, origin }); };

// Hooks
(function(){
  const serialize = msg => { try{ return typeof msg === 'string' ? msg : JSON.stringify(msg); }catch(e){ return String(msg); } };
  const OrigWS = global.WebSocket;
  global.WebSocket = function(...args){
    const ws = OrigWS(...args);
    addRuntimeLog3({ type:'WS.connect', data:serialize(args[0]) });
    const origSend = ws.send;
    ws.send = function(data){
      addRuntimeLog3({ type:'WS.send', data:serialize(data) });
      return origSend.apply(this, arguments);
    };
    ws.addEventListener('message', ev=>{
      addRuntimeLog3({ type:'WS.recv', data:serialize(ev.data) });
    });
    return ws;
  };

  const OrigES = global.EventSource;
  global.EventSource = function(...args){
    const es = OrigES(...args);
    addRuntimeLog3({ type:'SSE.connect', data:serialize(args[0]) });
    es.addEventListener('message', ev=>{
      addRuntimeLog3({ type:'SSE.message', data:serialize(ev.data) });
    });
    return es;
  };

  const origPM = global.postMessage;
  global.postMessage = function(message, targetOrigin, transfer){
    addRuntimeLog3({ type:'postMessage.send', data:serialize(message) });
    return origPM.call(this, message, targetOrigin, transfer);
  };
  global.addEventListener('message', ev=>{
    addRuntimeLog3({ type:'postMessage.receive', data:serialize(ev.data), origin: ev.origin });
  });
})();

// Trigger
const ws = new WebSocket('wss://example');
ws.send('hi');
ws.dispatch('message','reply');

const es = new EventSource('/sse');
es.dispatch('message','hello');

postMessage('ping','*');
postMessage({a:1},'*');

assert.deepStrictEqual(logs3[0], { type:'WS.connect', data:'wss://example' });
assert.deepStrictEqual(logs3[1], { type:'WS.send', data:'hi' });
assert.deepStrictEqual(logs3[2], { type:'WS.recv', data:'reply' });
assert.deepStrictEqual(logs3[3], { type:'SSE.connect', data:'/sse' });
assert.deepStrictEqual(logs3[4], { type:'SSE.message', data:'hello' });
assert.deepStrictEqual(logs3[5], { type:'postMessage.send', data:'ping' });
assert.deepStrictEqual(logs3[6], { type:'postMessage.receive', data:'ping', origin: '*' });
assert.deepStrictEqual(logs3[7], { type:'postMessage.send', data:'{"a":1}' });
assert.deepStrictEqual(logs3[8], { type:'postMessage.receive', data:'{"a":1}', origin: '*' });
assert.strictEqual(logs3.length,9);

console.log('WebSocket/EventSource/postMessage tests passed');
