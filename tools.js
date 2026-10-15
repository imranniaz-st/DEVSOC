// Small, dependable developer utilities. Everything runs locally in the popup.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
export function b64ToBytes(s) {
  let t = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const toHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');

export const CONVERT_MODES = [
  ['Encode', [['b64-enc', 'Base64 encode'], ['b64url-enc', 'Base64URL encode'], ['url-enc', 'URL encode'], ['html-enc', 'HTML entities encode'], ['hex-enc', 'Hex encode']]],
  ['Decode', [['b64-dec', 'Base64 decode'], ['b64url-dec', 'Base64URL decode'], ['url-dec', 'URL decode'], ['html-dec', 'HTML entities decode'], ['hex-dec', 'Hex decode']]],
  ['Hash', [['sha1', 'SHA-1'], ['sha256', 'SHA-256'], ['sha384', 'SHA-384'], ['sha512', 'SHA-512']]]
];

export async function convert(mode, input) {
  switch (mode) {
    case 'b64-enc': return bytesToB64(enc.encode(input));
    case 'b64url-enc': return bytesToB64(enc.encode(input)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    case 'b64-dec':
    case 'b64url-dec': return dec.decode(b64ToBytes(input));
    case 'url-enc': return encodeURIComponent(input);
    case 'url-dec': return decodeURIComponent(input.replace(/\+/g, ' '));
    case 'html-enc': return input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    case 'html-dec': {
      const t = document.createElement('textarea');
      t.innerHTML = input;
      return t.value;
    }
    case 'hex-enc': return toHex(enc.encode(input));
    case 'hex-dec': {
      const clean = input.replace(/0x/gi, '').replace(/[\s:,-]+/g, '');
      if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new Error('Hex input needs an even number of 0-9 and a-f characters.');
      const out = new Uint8Array(clean.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
      return dec.decode(out);
    }
    case 'sha1': case 'sha256': case 'sha384': case 'sha512': {
      const algo = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' }[mode];
      return toHex(new Uint8Array(await crypto.subtle.digest(algo, enc.encode(input))));
    }
    default: throw new Error('Unknown mode');
  }
}

function relative(sec) {
  const diff = Math.round(Date.now() / 1000 - sec);
  const abs = Math.abs(diff);
  const unit = abs < 60 ? [abs, 'second'] : abs < 3600 ? [Math.round(abs / 60), 'minute'] : abs < 86400 ? [Math.round(abs / 3600), 'hour'] : [Math.round(abs / 86400), 'day'];
  const label = unit[0] + ' ' + unit[1] + (unit[0] === 1 ? '' : 's');
  return diff >= 0 ? label + ' ago' : 'in ' + label;
}

export function parseTime(input) {
  const s = input.trim();
  if (!s) throw new Error('Enter a Unix timestamp or a date.');
  let ms;
  if (/^-?\d+(\.\d+)?$/.test(s)) {
    const n = parseFloat(s);
    ms = Math.abs(n) >= 1e12 ? n : n * 1000;
  } else {
    ms = Date.parse(s);
    if (Number.isNaN(ms)) throw new Error('Could not understand that date.');
  }
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) throw new Error('That timestamp is out of range.');
  return [
    ['Unix (seconds)', String(Math.floor(ms / 1000))],
    ['Unix (milliseconds)', String(Math.floor(ms))],
    ['UTC (ISO 8601)', d.toISOString()],
    ['Local time', d.toString()],
    ['Relative', relative(ms / 1000)]
  ];
}

export function jsonFormat(text, sort = false) {
  const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.keys(v).sort().reduce((o, k) => { o[k] = sortKeys(v[k]); return o; }, {}) : v;
  const v = JSON.parse(text);
  return JSON.stringify(sort ? sortKeys(v) : v, null, 2);
}
export function jsonMinify(text) { return JSON.stringify(JSON.parse(text)); }
// Finds the first JSON syntax error ourselves, so we can always report an exact line and column,
// whatever wording the browser's own JSON.parse error uses.
export function findJsonError(text) {
  let i = 0;
  const n = text.length;
  const err = (m) => { const e = new Error(m); e.pos = Math.min(i, Math.max(n - 1, 0)); throw e; };
  const ws = () => { while (i < n && ' \t\n\r'.includes(text[i])) i++; };
  const str = () => {
    i++;
    while (i < n) {
      const c = text[i];
      if (c === '"') { i++; return; }
      if (c === '\\') {
        i++;
        if (i >= n) break;
        if (text[i] === 'u') { if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 1, i + 5))) err('Invalid \\u escape'); i += 5; }
        else if ('"\\/bfnrt'.includes(text[i])) i++;
        else err('Invalid escape sequence');
        continue;
      }
      if (c < ' ') err('Raw line break or control character inside a string (use \\n)');
      i++;
    }
    err('Unterminated string');
  };
  const value = () => {
    ws();
    if (i >= n) err('Unexpected end of JSON');
    const c = text[i];
    if (c === '{') {
      i++; ws();
      if (text[i] === '}') { i++; return; }
      for (;;) {
        ws();
        if (text[i] !== '"') err('Expected a property name in double quotes');
        str(); ws();
        if (text[i] !== ':') err('Expected ":" after the property name');
        i++; value(); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return; }
        err('Expected "," or "}"');
      }
    }
    if (c === '[') {
      i++; ws();
      if (text[i] === ']') { i++; return; }
      for (;;) {
        value(); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return; }
        err('Expected "," or "]"');
      }
    }
    if (c === '"') { str(); return; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
    if (m) { i += m[0].length; return; }
    for (const lit of ['true', 'false', 'null']) if (text.startsWith(lit, i)) { i += lit.length; return; }
    err('Unexpected character "' + c + '"');
  };
  try {
    value(); ws();
    if (i < n) err('Unexpected text after the JSON value');
    return null;
  } catch (e) {
    if (e.pos === undefined) throw e;
    return { message: e.message, pos: e.pos };
  }
}

export function jsonErrorMessage(text, err) {
  const found = findJsonError(text);
  if (!found) return err.message;
  const before = text.slice(0, found.pos).split('\n');
  return found.message + ' (line ' + before.length + ', column ' + (before[before.length - 1].length + 1) + ')';
}

export function parseJwt(raw) {
  const token = String(raw).trim().replace(/^bearer\s+/i, '').replace(/\s+/g, '');
  if (!token) throw new Error('Paste a JWT to decode it.');
  const parts = token.split('.');
  if (parts.length === 5) throw new Error('This looks like an encrypted token (JWE). It cannot be read without the key.');
  if (parts.length !== 3) throw new Error('A JWT has three parts separated by dots. This has ' + parts.length + '.');
  const readJson = (p, label) => {
    try { return JSON.parse(dec.decode(b64ToBytes(p))); } catch (e) { throw new Error('The ' + label + ' is not valid Base64URL-encoded JSON.'); }
  };
  const header = readJson(parts[0], 'header');
  const payload = readJson(parts[1], 'payload');
  const checks = [];
  const add = (level, text) => checks.push({ level, text });
  const alg = String(header.alg || '');

  if (!alg) add('medium', 'No "alg" in the header.');
  if (alg.toLowerCase() === 'none') add('critical', 'Algorithm is "none": the token is unsigned. Test whether the server accepts it.');
  else if (/^HS/i.test(alg)) add('info', alg + ' tokens are signed with a shared secret. A weak secret can be guessed offline.');
  else if (/^(RS|PS|ES)/i.test(alg)) add('info', alg + ' is asymmetric. Test that the server rejects the same token re-signed with HS256 (algorithm confusion).');
  if (!parts[2]) add('high', 'The signature part is empty.');
  if ('kid' in header) add('info', 'Header has a "kid" (key ID). Test it for injection and path traversal.');
  ['jku', 'x5u', 'jwk'].forEach((k) => { if (k in header) add('medium', 'Header has "' + k + '", which points at or carries a signing key. Check that the server does not trust it blindly.'); });

  const now = Date.now() / 1000;
  const times = [];
  [['exp', 'Expires'], ['iat', 'Issued'], ['nbf', 'Not before']].forEach(([k, label]) => {
    if (typeof payload[k] === 'number') times.push([label + ' (' + k + ')', new Date(payload[k] * 1000).toISOString() + '  ·  ' + relative(payload[k])]);
  });
  if (typeof payload.exp !== 'number') add('low', 'No "exp" claim: this token never expires.');
  else {
    if (payload.exp < now) add('info', 'This token has expired ' + relative(payload.exp) + '.');
    const life = typeof payload.iat === 'number' ? payload.exp - payload.iat : payload.exp - now;
    if (life > 365 * 86400) add('low', 'Very long lifetime (over a year).');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now) add('info', 'The token is not valid yet ("nbf" is in the future).');
  if (!('aud' in payload) && !('iss' in payload)) add('info', 'No "iss" or "aud" claim. Check that tokens from other services are rejected.');

  return { header, payload, times, checks, signatureLength: parts[2].length };
}
