const assert = require('assert');

const RX_S3_VHOST = /https?:\/\/([a-z0-9.\-]+)\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\/[^\s"'<>]*/gi;
const RX_S3_PATH  = /https?:\/\/s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
const RX_GCS_HOST = /https?:\/\/([a-z0-9.\-]+)\.storage\.googleapis\.com\/[^\s"'<>]*/gi;
const RX_GCS_PATH = /https?:\/\/storage\.googleapis\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
const RX_DO_SPACE = /https?:\/\/([a-z0-9.\-]+)\.([a-z0-9-]+)\.digitaloceanspaces\.com\/[^\s"'<>]*/gi;
const RX_CF_R2    = /https?:\/\/([a-z0-9-]+)\.r2\.cloudflarestorage\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
const RX_OSS_VHOST= /https?:\/\/([a-z0-9.\-]+)\.oss-([a-z0-9-]+)\.aliyuncs\.com\/[^\s"'<>]*/gi;
const RX_OSS_PATH = /https?:\/\/oss-([a-z0-9-]+)\.aliyuncs\.com\/([a-z0-9.\-]+)\/[^\s"'<>]*/gi;
const RX_AZURE_BL = /https?:\/\/([a-z0-9-]+)\.blob\.core\.windows\.net\/([a-z0-9\-]+)\/[^\s"'<>]*/gi;
const RX_AZURE_DFS= /https?:\/\/([a-z0-9-]+)\.dfs\.core\.windows\.net\/([a-z0-9\-]+)\/[^\s"'<>]*/gi;

function scanTextForBuckets(text){
  const out = [];
  let m;
  while ((m = RX_S3_VHOST.exec(text))) out.push({provider:'S3',style:'vhost',bucket:m[1]});
  while ((m = RX_S3_PATH.exec(text)))  out.push({provider:'S3',style:'path',bucket:m[1]});
  while ((m = RX_GCS_HOST.exec(text))) out.push({provider:'GCS',style:'vhost',bucket:m[1]});
  while ((m = RX_GCS_PATH.exec(text))) out.push({provider:'GCS',style:'path',bucket:m[1]});
  while ((m = RX_DO_SPACE.exec(text))) out.push({provider:'DO',style:'vhost',bucket:m[1],region:m[2]});
  while ((m = RX_CF_R2.exec(text)))  out.push({provider:'R2',style:'path',account:m[1],bucket:m[2]});
  while ((m = RX_OSS_VHOST.exec(text))) out.push({provider:'OSS',style:'vhost',bucket:m[1],region:m[2]});
  while ((m = RX_OSS_PATH.exec(text)))  out.push({provider:'OSS',style:'path',bucket:m[2],region:m[1]});
  while ((m = RX_AZURE_BL.exec(text))) out.push({provider:'AZURE',style:'blob',account:m[1],container:m[2]});
  while ((m = RX_AZURE_DFS.exec(text))) out.push({provider:'AZURE',style:'dfs',account:m[1],container:m[2]});
  return out;
}

const samples = [
  {url:'https://mybucket.s3.amazonaws.com/file.txt', provider:'S3', style:'vhost', bucket:'mybucket'},
  {url:'https://s3.amazonaws.com/mybucket/file.txt', provider:'S3', style:'path', bucket:'mybucket'},
  {url:'https://mybucket.storage.googleapis.com/file.txt', provider:'GCS', style:'vhost', bucket:'mybucket'},
  {url:'https://storage.googleapis.com/mybucket/file.txt', provider:'GCS', style:'path', bucket:'mybucket'},
  {url:'https://mybucket.nyc3.digitaloceanspaces.com/file.txt', provider:'DO', style:'vhost', bucket:'mybucket', region:'nyc3'},
  {url:'https://abc123.r2.cloudflarestorage.com/mybucket/file.txt', provider:'R2', style:'path', bucket:'mybucket', account:'abc123'},
  {url:'https://mybucket.oss-cn-shanghai.aliyuncs.com/file.txt', provider:'OSS', style:'vhost', bucket:'mybucket', region:'cn-shanghai'},
  {url:'https://oss-cn-shanghai.aliyuncs.com/mybucket/file.txt', provider:'OSS', style:'path', bucket:'mybucket', region:'cn-shanghai'},
  {url:'https://account.blob.core.windows.net/container/file.txt', provider:'AZURE', style:'blob', account:'account', container:'container'},
  {url:'https://account.dfs.core.windows.net/container/file.txt', provider:'AZURE', style:'dfs', account:'account', container:'container'}
];

samples.forEach(s => {
  const res = scanTextForBuckets(s.url)[0];
  assert(res, `No match for ${s.url}`);
  assert.strictEqual(res.provider, s.provider);
  assert.strictEqual(res.style, s.style);
  if (s.bucket) assert.strictEqual(res.bucket, s.bucket);
  if (s.region) assert.strictEqual(res.region, s.region);
  if (s.account) assert.strictEqual(res.account, s.account);
  if (s.container) assert.strictEqual(res.container, s.container);
});

console.log('All bucket regex tests passed');
