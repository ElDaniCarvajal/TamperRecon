const assert = require('assert');

const escHTML = s => String(s ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
const highlightEnc = text => {
  let out = text;
  if (typeof atob === 'function') {
    out = out.replace(/\b[A-Za-z0-9+/]{20,}={0,2}\b/g, b64 => {
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

assert.ok(highlightEnc('aGVsbG93b3JsZGhlbGxvd29ybGQ=').includes('ptk-b64'));
assert.ok(highlightEnc('68656c6c6f20776f726c64').includes('ptk-hex'));
const ambiguous = highlightEnc('aCA0aCA0aCA0aCA0aCA0');
assert.ok(ambiguous.includes('ptk-hex') && !ambiguous.includes('ptk-b64'));
console.log('highlightEnc tests passed');
