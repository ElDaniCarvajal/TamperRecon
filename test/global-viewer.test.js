const assert = require('assert');
const { createGlobalViewer } = require('../main');

function makeEl(tag){
  return {
    tag,
    textContent: '',
    children: [],
    addEventListener(event, cb){ this['on'+event] = cb; },
    appendChild(child){ this.children.push(child); },
  };
}

global.document = {
  body: makeEl('body'),
  createElement: makeEl
};

  const base = new Set(Object.getOwnPropertyNames(global));
  global.testNumber = 7;
  global.testFunc = function(){ return 'ok'; };

  const { container, output } = createGlobalViewer(global, base);

  assert.deepStrictEqual(container.children.map(c=>c.textContent), ['testNumber','testFunc']);

const btnNum = container.children.find(el => el.textContent === 'testNumber');
btnNum.onclick();
assert.strictEqual(output.textContent, '7');

const btnFunc = container.children.find(el => el.textContent === 'testFunc');
btnFunc.onclick();
assert.strictEqual(output.textContent, JSON.stringify('ok', null, 2));

console.log('global viewer tests passed');
