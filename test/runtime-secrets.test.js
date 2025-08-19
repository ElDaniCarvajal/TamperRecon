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
