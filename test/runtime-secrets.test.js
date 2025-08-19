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
