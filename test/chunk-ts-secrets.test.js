const assert = require('assert');
const { scanChunksAndTs } = require('../main');

const files = {
  'app.chunk.js': "const apiKey = 'abc'; fetch('https://api.example.com/v1');",
  'src/util.ts': "const password = 'p@ss'; const ip='192.168.0.1'; const dom='example.org';",
  'main.js': "const token = 'ignored'; const url='http://ignored.com';",
};

const findings = scanChunksAndTs(files);

assert.deepStrictEqual(findings, [
  { file: 'app.chunk.js', type:'secret', match:'apiKey' },
  { file: 'app.chunk.js', type:'endpoint', match:'https://api.example.com/v1' },
  { file: 'src/util.ts', type:'secret', match:'password' },
  { file: 'src/util.ts', type:'ip', match:'192.168.0.1' },
  { file: 'src/util.ts', type:'domain', match:'example.org' }
]);

console.log('chunk and ts scan tests passed');
