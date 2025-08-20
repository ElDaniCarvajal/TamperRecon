const assert = require('assert');
const { scanChunksAndTs } = require('../main');

const files = {
  'app.chunk.js': "const apiKey = 'abc'; fetch('https://api.example.com/v1'); const cfg={name:'WEBPAGEAFORE',meta:{cat:'GESTORUSUARIOSSIGNIN'}};",
  'src/util.ts': "const password = 'p@ss'; const dom='example.org';",
  'main-es2015.js': "r.CONFIG_MS={name:r.APP_NAME,category:'GESTOR'}; const ip='192.168.0.1';",
};

const findings = scanChunksAndTs(files);

assert.deepStrictEqual(findings, [
  { file: 'app.chunk.js', type:'secret', match:'apiKey' },
  { file: 'app.chunk.js', type:'endpoint', match:'https://api.example.com/v1' },
  { file: 'app.chunk.js', type:'json', match:"{name:'WEBPAGEAFORE',meta:{cat:'GESTORUSUARIOSSIGNIN'}}" },
  { file: 'app.chunk.js', type:'json', match:"{cat:'GESTORUSUARIOSSIGNIN'}" },
  { file: 'src/util.ts', type:'secret', match:'password' },
  { file: 'src/util.ts', type:'domain', match:'example.org' },
  { file: 'main-es2015.js', type:'ip', match:'192.168.0.1' },
  { file: 'main-es2015.js', type:'json', match:"{name:r.APP_NAME,category:'GESTOR'}" }
]);

console.log('chunk and ts scan tests passed');
