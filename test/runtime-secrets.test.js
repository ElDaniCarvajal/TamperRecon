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

// === Scan AC_DATA and localStorage ===

const logs2 = [];
function addRuntimeLog2(rec){
  logs2.push(rec);
}

const PATTERNS = [{ rx:/(api[_-]?key|token|secret)/i }];

function matchesSecret(str){
  if (typeof str !== 'string') return false;
  for (const p of PATTERNS){
    p.rx.lastIndex = 0;
    if (p.rx.test(str)) return true;
  }
  return false;
}

function scanACData(){
  const seen = new WeakSet();
  function walk(obj, path){
    if (typeof obj === 'string'){
      if (matchesSecret(obj) || matchesSecret(path)) addRuntimeLog2({ type:'AC_DATA', key:path, data:obj });
      return;
    }
    if (obj && typeof obj === 'object'){
      if (seen.has(obj)) return; seen.add(obj);
      Object.entries(obj).forEach(([k,v])=>walk(v, path?path+'.'+k:k));
    }
  }
  if (global.AC_DATA) walk(global.AC_DATA, 'AC_DATA');
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

global.AC_DATA = { foo:{ token:'abc123' }, other:'none' };
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

scanACData();
scanLocalStorage();
scanSessionStorage();
scanCookies();

assert.deepStrictEqual(logs2[0], { type:'AC_DATA', key:'AC_DATA.foo.token', data:'abc123' });
assert.deepStrictEqual(logs2[1], { type:'localStorage', key:'apiKey', data:'token-XYZ' });
assert.deepStrictEqual(logs2[2], { type:'sessionStorage', key:'sessionToken', data:'abc-session' });
assert.deepStrictEqual(logs2[3], { type:'cookie', key:'apiKey', data:'secret123' });
assert.strictEqual(logs2.length,4);

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
  const OrigWS = global.WebSocket;
  global.WebSocket = function(...args){
    const ws = OrigWS(...args);
    addRuntimeLog3({ type:'WS.connect', data:String(args[0]) });
    const origSend = ws.send;
    ws.send = function(data){
      addRuntimeLog3({ type:'WS.send', data:String(data) });
      return origSend.apply(this, arguments);
    };
    ws.addEventListener('message', ev=>{
      addRuntimeLog3({ type:'WS.recv', data:String(ev.data) });
    });
    return ws;
  };

  const OrigES = global.EventSource;
  global.EventSource = function(...args){
    const es = OrigES(...args);
    addRuntimeLog3({ type:'SSE.connect', data:String(args[0]) });
    es.addEventListener('message', ev=>{
      addRuntimeLog3({ type:'SSE.message', data:String(ev.data) });
    });
    return es;
  };

  const origPM = global.postMessage;
  global.postMessage = function(message, targetOrigin, transfer){
    addRuntimeLog3({ type:'postMessage.send', data:String(message) });
    return origPM.call(this, message, targetOrigin, transfer);
  };
  global.addEventListener('message', ev=>{
    addRuntimeLog3({ type:'postMessage.receive', data:String(ev.data), origin: ev.origin });
  });
})();

// Trigger
const ws = new WebSocket('wss://example');
ws.send('hi');
ws.dispatch('message','reply');

const es = new EventSource('/sse');
es.dispatch('message','hello');

postMessage('ping','*');

assert.deepStrictEqual(logs3[0], { type:'WS.connect', data:'wss://example' });
assert.deepStrictEqual(logs3[1], { type:'WS.send', data:'hi' });
assert.deepStrictEqual(logs3[2], { type:'WS.recv', data:'reply' });
assert.deepStrictEqual(logs3[3], { type:'SSE.connect', data:'/sse' });
assert.deepStrictEqual(logs3[4], { type:'SSE.message', data:'hello' });
assert.deepStrictEqual(logs3[5], { type:'postMessage.send', data:'ping' });
assert.deepStrictEqual(logs3[6], { type:'postMessage.receive', data:'ping', origin: '*' });
assert.strictEqual(logs3.length,7);

console.log('WebSocket/EventSource/postMessage tests passed');
