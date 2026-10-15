// These two functions are injected into the page you are viewing, ONLY when you press "Scan this page".
// They must stay self-contained (no outside variables). They never send data anywhere:
// the only network call is one same-origin GET for the current page and its own script files.

export async function collectPageData() {
  const d = {
    url: location.href, origin: location.origin, hostname: location.hostname,
    https: location.protocol === 'https:', title: document.title,
    headers: null, headerError: null, mixed: [], forms: [], noSri: [], blankLinks: 0,
    secrets: [], tokens: [], storageKeys: [], sourceMaps: [], tech: [], scriptsScanned: 0
  };
  const uniq = (arr) => Array.from(new Set(arr));
  const mask = (v) => (v.length <= 12 ? v.slice(0, 2) + '…' : v.slice(0, 4) + '…' + v.slice(-2) + ' (' + v.length + ' chars)');

  try {
    const r = await fetch(location.href, { credentials: 'same-origin', cache: 'no-store' });
    const hd = {};
    r.headers.forEach((v, k) => { hd[k] = v; });
    d.headers = hd;
  } catch (e) { d.headerError = String((e && e.message) || e); }

  if (d.https) {
    document.querySelectorAll('script[src],link[href],img[src],iframe[src],audio[src],video[src],source[src]').forEach((n) => {
      const u = n.src || n.href;
      if (typeof u === 'string' && u.indexOf('http://') === 0) d.mixed.push(u);
    });
    d.mixed = uniq(d.mixed).slice(0, 12);
  }

  Array.from(document.forms).slice(0, 40).forEach((f) => {
    const action = f.action || location.href;
    d.forms.push({ action: String(action).slice(0, 200), hasPassword: !!f.querySelector('input[type=password]'), insecureAction: d.https && String(action).indexOf('http://') === 0 });
  });

  document.querySelectorAll('script[src]').forEach((s) => {
    try { if (new URL(s.src).origin !== location.origin && !s.integrity) d.noSri.push(s.src); } catch (e) { /* ignore */ }
  });
  d.noSri = uniq(d.noSri).slice(0, 15);

  document.querySelectorAll('a[target=_blank]').forEach((a) => {
    if (!/noopener|noreferrer/i.test(a.rel || '')) d.blankLinks++;
  });

  const patterns = [
    ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'high', false],
    ['Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/g, 'medium', false],
    ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'high', false],
    ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, 'high', false],
    ['Stripe live secret key', /\bsk_live_[0-9a-zA-Z]{20,}\b/g, 'critical', false],
    ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, 'critical', true],
    ['Hard-coded credential', /(?:api[_-]?key|secret|passwd|password|access[_-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-\/+=]{16,})["']/gi, 'low', false]
  ];
  const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b/g;
  const seen = new Set();
  const placeholder = /example|your|xxxx|placeholder|changeme|dummy|sample|0000/i;

  const scan = (text, source) => {
    for (const [type, re, severity, noMask] of patterns) {
      re.lastIndex = 0;
      let m; let n = 0;
      while ((m = re.exec(text)) && n++ < 5) {
        const val = m[1] || m[0];
        if (type === 'Hard-coded credential' && (placeholder.test(val) || /^(.)\1+$/.test(val))) continue;
        const key = type + val;
        if (seen.has(key)) continue;
        seen.add(key);
        d.secrets.push({ type, severity, source: source.slice(0, 160), masked: noMask ? val : mask(val),
          note: type === 'Google API key' ? 'Google API keys are often meant to be public, but check that this one is restricted by domain and API in the Google Cloud console.' : '' });
      }
    }
    jwtRe.lastIndex = 0;
    let t; let c = 0;
    while ((t = jwtRe.exec(text)) && c++ < 3) {
      if (!d.tokens.some((x) => x.value === t[0])) d.tokens.push({ where: source.slice(0, 100), value: t[0], masked: mask(t[0]) });
    }
  };

  try { scan(document.documentElement.outerHTML.slice(0, 1000000), 'page HTML'); } catch (e) { /* ignore */ }

  const sameOriginScripts = uniq(Array.from(document.querySelectorAll('script[src]')).map((s) => s.src).filter((u) => {
    try { return new URL(u).origin === location.origin; } catch (e) { return false; }
  })).slice(0, 12);
  for (const u of sameOriginScripts) {
    try {
      const r = await fetch(u, { credentials: 'same-origin' });
      if (!r.ok) continue;
      const text = (await r.text()).slice(0, 1500000);
      d.scriptsScanned++;
      scan(text, u);
      const sm = /\/\/[#@]\s*sourceMappingURL=(\S+)/.exec(text.slice(-2000));
      if (sm) d.sourceMaps.push(u.split('/').pop().split('?')[0] + ' -> ' + sm[1].slice(0, 80));
    } catch (e) { /* skip files we cannot read */ }
  }

  const keyRe = /token|jwt|secret|passw|auth|session|api[_-]?key/i;
  [['localStorage', 'localStorage'], ['sessionStorage', 'sessionStorage']].forEach(([label, prop]) => {
    try {
      const st = window[prop];
      for (let i = 0; i < st.length && i < 200; i++) {
        const k = st.key(i);
        const v = String(st.getItem(k) || '');
        if (keyRe.test(k)) d.storageKeys.push({ where: label, key: k.slice(0, 80) });
        jwtRe.lastIndex = 0;
        const m = jwtRe.exec(v);
        if (m && !d.tokens.some((x) => x.value === m[0])) d.tokens.push({ where: label + '["' + k.slice(0, 40) + '"]', value: m[0], masked: mask(m[0]) });
      }
    } catch (e) { /* storage may be blocked */ }
  });
  try {
    document.cookie.split(';').forEach((p) => {
      const i = p.indexOf('=');
      if (i < 0) return;
      jwtRe.lastIndex = 0;
      const m = jwtRe.exec(p.slice(i + 1));
      if (m && !d.tokens.some((x) => x.value === m[0])) d.tokens.push({ where: 'cookie "' + p.slice(0, i).trim().slice(0, 40) + '"', value: m[0], masked: mask(m[0]) });
    });
  } catch (e) { /* ignore */ }
  d.tokens = d.tokens.slice(0, 8);

  // Technology hints that can be read from the page itself (no page globals needed here)
  const add = (name, version) => d.tech.push({ name, version: version || '' });
  const gen = document.querySelector('meta[name=generator]');
  if (gen && gen.content) {
    const g = gen.content.slice(0, 60);
    add(/wordpress/i.test(g) ? 'WordPress' : g.split(' ')[0], (/\d+(\.\d+)+/.exec(g) || [''])[0]);
  }
  const ng = document.querySelector('[ng-version]');
  if (ng) add('Angular', ng.getAttribute('ng-version'));
  const srcs = Array.from(document.querySelectorAll('script[src],link[href]')).map((n) => n.src || n.href).join(' ');
  if (/wp-content|wp-includes/.test(srcs) && !d.tech.some((t) => t.name === 'WordPress')) add('WordPress');
  if (/cdn\.shopify\.com/.test(srcs)) add('Shopify');
  if (/\/_next\//.test(srcs)) add('Next.js');
  if (/\/_nuxt\//.test(srcs)) add('Nuxt');
  if (/googletagmanager\.com/.test(srcs)) add('Google Tag Manager');
  if (/cloudflare/i.test(srcs)) add('Cloudflare (scripts)');
  return d;
}

// Runs in the page's own JavaScript world so it can read library version globals. Read-only.
export function detectGlobals() {
  const out = [];
  const add = (name, version) => out.push({ name, version: version ? String(version).slice(0, 20) : '' });
  try { if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) add('jQuery', window.jQuery.fn.jquery); } catch (e) { /* ignore */ }
  try { if (window.React && window.React.version) add('React', window.React.version); } catch (e) { /* ignore */ }
  try { if (window.Vue && window.Vue.version) add('Vue', window.Vue.version); } catch (e) { /* ignore */ }
  try { if (window.angular && window.angular.version) add('AngularJS', window.angular.version.full); } catch (e) { /* ignore */ }
  try { if (window.__NEXT_DATA__) add('Next.js'); } catch (e) { /* ignore */ }
  try { if (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) add('Bootstrap', window.bootstrap.Tooltip.VERSION); } catch (e) { /* ignore */ }
  try { if (window._ && window._.VERSION) add('Lodash', window._.VERSION); } catch (e) { /* ignore */ }
  try { if (window.Shopify) add('Shopify'); } catch (e) { /* ignore */ }
  return out;
}
