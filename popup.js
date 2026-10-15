import { analyzePage, analyzeCookies, score, sortFindings, SEVERITIES, SEV_LABEL } from './analyze.js';
import { collectPageData, detectGlobals } from './scanner.js';
import { parseJwt, convert, CONVERT_MODES, parseTime, jsonFormat, jsonMinify, jsonErrorMessage, bytesToB64 } from './tools.js';
import { toMarkdown, toHtml } from './report.js';

const $ = (sel) => document.querySelector(sel);

// Safe DOM builder: page-derived text is only ever added with textContent, never as HTML.
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([k, v]) => {
    if (v === false || v == null) return;
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  });
  kids.flat().forEach((c) => { if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c))); });
  return n;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}
async function copyText(text, msg = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(msg); } catch (e) { toast('Copy was blocked by the browser'); }
}
function setStatus(node, msg, kind) {
  node.textContent = msg || '';
  node.className = 'status' + (kind ? ' ' + kind : '');
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

/* ---------- Tabs ---------- */
const tabs = Array.from(document.querySelectorAll('[role=tab]'));
function activate(name, focus) {
  tabs.forEach((t) => {
    const on = t.dataset.tab === name;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    $('#' + t.getAttribute('aria-controls')).hidden = !on;
    if (on && focus) t.focus();
  });
  if (name === 'network' && typeof syncNetUi === 'function') syncNetUi();
}
tabs.forEach((t, i) => {
  t.addEventListener('click', () => activate(t.dataset.tab));
  t.addEventListener('keydown', (e) => {
    const k = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
    if (k) { e.preventDefault(); activate(tabs[(i + k + tabs.length) % tabs.length].dataset.tab, true); }
    else if (e.key === 'Home') { e.preventDefault(); activate(tabs[0].dataset.tab, true); }
    else if (e.key === 'End') { e.preventDefault(); activate(tabs[tabs.length - 1].dataset.tab, true); }
  });
});

/* ---------- Storage ---------- */
const store = {
  async get(key, fallback) { const r = await chrome.storage.local.get(key); return r[key] ?? fallback; },
  set(key, value) { return chrome.storage.local.set({ [key]: value }); }
};
let saved = [];
const fid = (f) => [f.category, f.title, f.url].join('|');

async function addToReport(list, url) {
  let added = 0;
  list.forEach((f) => {
    const item = { ...f, url: url || '' };
    if (!saved.some((s) => fid(s) === fid(item))) { saved.push(item); added++; }
  });
  await store.set('findings', saved);
  renderReport();
  toast(added ? 'Added to report' : 'Already in report');
  return added;
}

/* ---------- Scan ---------- */
const state = { tab: null, findings: [], cookieFindings: [], tokens: [], tech: [], filter: 'all', cookieInfo: null, scanned: false };

// Side panel stays open across focus changes. Prefer the last-focused browser
// window; currentWindow alone can miss the page tab after the popup→panel move.
async function currentTab() {
  for (const query of [
    { active: true, lastFocusedWindow: true },
    { active: true, currentWindow: true }
  ]) {
    const [tab] = await chrome.tabs.query(query);
    if (tab && tab.id != null) return tab;
  }
  const actives = await chrome.tabs.query({ active: true });
  return actives[0] || null;
}

function tabUrl(tab) {
  return (tab && (tab.url || tab.pendingUrl)) || '';
}
const isWeb = (tab) => /^https?:/i.test(tabUrl(tab));

function restrictedScanMessage(tab) {
  const url = tabUrl(tab);
  if (!tab) {
    return 'Could not find the active browser tab. Click a normal website tab, then scan again.';
  }
  if (!url) {
    return 'Could not read this tab\'s address. Click the DevSec Toolkit icon on a normal website, then try again.';
  }
  if (/^chrome:\/\//i.test(url) || /^chrome-extension:\/\//i.test(url) || /^edge:\/\//i.test(url) || /^about:/i.test(url)) {
    return 'This tab is a browser page (' + url.split('/')[0] + '//…), not a website. Open an http or https page in the main tab, then scan again.';
  }
  if (/chrome\.google\.com\/webstore/i.test(url) || /chromewebstore\.google\.com/i.test(url)) {
    return 'Chrome blocks extensions on the Web Store. Open a regular website and try again.';
  }
  return 'Open a regular website (http or https) and try again. Chrome does not let extensions run on its own pages or the Web Store.';
}

// Side-panel button clicks do not grant activeTab the way opening a popup did.
// Fall back to optional host permission for this origin when injection is blocked.
async function execInTab(tab, func, world) {
  const opts = { target: { tabId: tab.id }, func };
  if (world) opts.world = world;
  try {
    return await chrome.scripting.executeScript(opts);
  } catch (first) {
    const origin = new URL(tab.url).origin + '/*';
    let granted = false;
    try { granted = await chrome.permissions.request({ origins: [origin] }); } catch (e) { /* declined */ }
    if (!granted) throw first;
    return await chrome.scripting.executeScript(opts);
  }
}

async function runScan() {
  const status = $('#scan-status'), btn = $('#scan-btn');
  setStatus(status, '');
  const tab = await currentTab();
  if (!isWeb(tab)) {
    setStatus(status, restrictedScanMessage(tab), 'err');
    return;
  }
  state.tab = tab;
  btn.disabled = true; btn.textContent = 'Scanning…';
  setStatus(status, 'Reading the page and its scripts…');
  try {
    const [{ result: data }] = await execInTab(tab, collectPageData);
    let globals = [];
    try {
      const [g] = await execInTab(tab, detectGlobals, 'MAIN');
      globals = (g && g.result) || [];
    } catch (e) { /* optional */ }
    const tech = [];
    [...globals, ...data.tech].forEach((t) => { if (!tech.some((x) => x.name === t.name)) tech.push(t); });
    data.tech = tech;
    state.findings = analyzePage(data);
    state.tokens = data.tokens || [];
    state.tech = tech;
    state.cookieFindings = []; state.cookieInfo = null; state.scanned = true; state.https = data.https;
    state.scriptsScanned = data.scriptsScanned;
    $('#site').textContent = data.hostname;
    $('#scan-intro').hidden = true;
    setStatus(status, 'Done. Checked headers, page code and ' + data.scriptsScanned + ' script file(s).', 'ok');
    renderScan();
  } catch (e) {
    setStatus(status, 'Chrome would not let the scan run here: ' + (e && e.message ? e.message : e) + ' Reload the page and try again.', 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Scan again';
  }
}

function findingCard(f) {
  const isSaved = saved.some((s) => fid(s) === fid({ ...f, url: state.tab ? state.tab.url : '' }));
  const add = el('button', { class: 'small ghost', disabled: isSaved, onclick: async (e) => {
    await addToReport([f], state.tab ? state.tab.url : '');
    e.target.textContent = 'Added'; e.target.disabled = true;
  } }, isSaved ? 'Added' : 'Add to report');
  return el('details', { class: 'finding sev-' + f.severity },
    el('summary', null, el('span', { class: 'badge' }, SEV_LABEL[f.severity]), el('span', null, f.title)),
    el('div', { class: 'fbody' },
      el('p', null, f.detail),
      f.evidence ? el('pre', null, f.evidence) : null,
      el('p', { class: 'fix' }, el('strong', null, 'How to fix: '), f.fix),
      add));
}

function renderScan() {
  const box = $('#scan-results');
  box.replaceChildren();
  if (!state.scanned) return;
  const all = sortFindings([...state.findings, ...state.cookieFindings]);
  const s = score(all);
  const noun = all.length === 1 ? 'finding' : 'findings';
  const headline = s.grade === 'A' ? 'Looks solid' : s.grade === 'B' ? 'Good, with a few gaps' : s.grade === 'C' ? 'Needs attention' : 'Needs work';
  box.append(el('div', { class: 'score' },
    el('div', { class: 'grade g-' + s.grade, 'aria-label': 'Grade ' + s.grade }, s.grade),
    el('div', { class: 'txt' }, el('strong', null, headline),
      el('p', null, all.length + ' ' + noun + ' · ' + s.counts.critical + ' critical, ' + s.counts.high + ' high, ' + s.counts.medium + ' medium'),
      el('p', null, 'Score ' + s.score + '/100 from passive checks only'))));

  if (all.length) {
    const chips = el('div', { class: 'chips', role: 'group', 'aria-label': 'Filter by severity' });
    ['all', ...SEVERITIES].forEach((k) => {
      const n = k === 'all' ? all.length : s.counts[k];
      if (k !== 'all' && !n) return;
      chips.append(el('button', { class: 'chip', 'aria-pressed': String(state.filter === k), onclick: () => { state.filter = k; renderScan(); } },
        (k === 'all' ? 'All' : SEV_LABEL[k]) + ' ' + n));
    });
    box.append(chips);
    all.filter((f) => state.filter === 'all' || f.severity === state.filter).forEach((f) => box.append(findingCard(f)));
    box.append(el('div', { class: 'row' }, el('button', { class: 'ghost small', onclick: () => addToReport(all.filter((f) => f.severity !== 'info'), state.tab.url) }, 'Add all (except info) to report')));
  } else {
    box.append(el('p', { class: 'empty' }, 'No issues found by the passive checks. Nice work. Manual testing is still worth doing.'));
  }

  if (state.tokens.length) {
    box.append(el('p', { class: 'sec-title' }, 'Tokens found'));
    state.tokens.forEach((t) => box.append(el('div', { class: 'tokrow' },
      el('code', { title: t.where }, t.where + ' · ' + t.masked),
      el('button', { class: 'small', onclick: () => { $('#jwt-in').value = t.value; $('#jwt-in').dispatchEvent(new Event('input')); activate('jwt'); } }, 'Decode'))));
  }
  if (state.tech.length) {
    box.append(el('p', { class: 'sec-title' }, 'Technology detected'));
    box.append(el('div', { class: 'tags' }, state.tech.map((t) => el('span', { class: 'tag' }, t.name + (t.version ? ' ' + t.version : '')))));
  }

  const cookieBox = el('div', { class: 'cookie-box card' });
  if (state.cookieInfo === null) {
    cookieBox.append(el('h2', null, 'Check cookie flags'),
      el('p', null, 'Needs one extra permission, for this site only: Chrome will ask. You can remove it afterwards.'),
      el('button', { onclick: checkCookies }, 'Check cookies'));
  } else {
    cookieBox.append(el('h2', null, 'Cookies checked'),
      el('p', null, state.cookieInfo + ' cookie(s) read locally for this site.'),
      el('button', { class: 'link', onclick: removeCookieAccess }, 'Remove cookie access'));
  }
  box.append(cookieBox);
}

async function checkCookies() {
  if (!state.tab) return;
  const origin = new URL(state.tab.url).origin;
  let granted = false;
  try { granted = await chrome.permissions.request({ permissions: ['cookies'], origins: [origin + '/*'] }); } catch (e) { /* declined */ }
  if (!granted) { toast('No permission given, so no cookies were read'); return; }
  const cookies = await chrome.cookies.getAll({ url: state.tab.url });
  state.cookieFindings = analyzeCookies(cookies, state.https);
  state.cookieInfo = cookies.length;
  renderScan();
}
async function removeCookieAccess() {
  const origin = new URL(state.tab.url).origin;
  try { await chrome.permissions.remove({ permissions: ['cookies'], origins: [origin + '/*'] }); toast('Cookie access removed'); } catch (e) { toast('Could not remove access'); }
}
$('#scan-btn').addEventListener('click', runScan);

/* ---------- JWT ---------- */
const jwtIn = $('#jwt-in');
function jwtRender() {
  const out = $('#jwt-out'), status = $('#jwt-status');
  out.replaceChildren();
  if (!jwtIn.value.trim()) { setStatus(status, ''); return; }
  try {
    const r = parseJwt(jwtIn.value);
    setStatus(status, 'Decoded locally. The signature is not verified (that needs the key).', 'ok');
    out.append(
      el('p', { class: 'sec-title' }, 'Header'), el('pre', null, JSON.stringify(r.header, null, 2)),
      el('p', { class: 'sec-title' }, 'Payload'), el('pre', null, JSON.stringify(r.payload, null, 2)));
    if (r.times.length) out.append(el('dl', { class: 'kv' }, r.times.flatMap(([k, v]) => [el('dt', null, k), el('dd', null, v)])));
    out.append(el('p', { class: 'sec-title' }, 'What to look at'));
    r.checks.forEach((c) => out.append(el('div', { class: 'check' }, el('span', { class: 'lvl ' + c.level }, SEV_LABEL[c.level]), el('span', null, c.text))));
    const notable = r.checks.filter((c) => c.level !== 'info');
    if (notable.length) {
      out.append(el('button', { class: 'ghost small mt', onclick: () => addToReport(notable.map((c) => ({
        category: 'JWT', severity: c.level, title: 'JWT: ' + c.text.split(/[.:]/)[0], detail: c.text,
        fix: 'Review the token configuration and signing practices.', evidence: 'alg: ' + (r.header.alg || 'n/a')
      })), state.tab ? state.tab.url : '') }, 'Add notable checks to report'));
    }
  } catch (e) { setStatus(status, e.message, 'err'); }
}
jwtIn.addEventListener('input', debounce(jwtRender, 150));
$('#jwt-clear').addEventListener('click', () => { jwtIn.value = ''; jwtRender(); jwtIn.focus(); });
$('#jwt-sample').addEventListener('click', () => {
  const enc = (o) => bytesToB64(new TextEncoder().encode(JSON.stringify(o))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const now = Math.floor(Date.now() / 1000);
  jwtIn.value = enc({ alg: 'HS256', typ: 'JWT' }) + '.' + enc({ sub: '1234567890', name: 'Sample User', role: 'admin', iat: now - 3600, exp: now + 3600 }) + '.c2FtcGxlLXNpZ25hdHVyZQ';
  jwtRender();
});

/* ---------- Convert ---------- */
const cvMode = $('#cv-mode'), cvIn = $('#cv-in'), cvOut = $('#cv-out');
CONVERT_MODES.forEach(([group, items]) => cvMode.append(el('optgroup', { label: group }, items.map(([v, l]) => el('option', { value: v }, l)))));
async function cvRun() {
  const status = $('#cv-status');
  if (!cvIn.value) { cvOut.value = ''; setStatus(status, ''); return; }
  try { cvOut.value = await convert(cvMode.value, cvIn.value); setStatus(status, ''); }
  catch (e) { cvOut.value = ''; setStatus(status, 'Could not convert: ' + e.message, 'err'); }
}
cvIn.addEventListener('input', debounce(cvRun, 120));
cvMode.addEventListener('change', cvRun);
$('#cv-copy').addEventListener('click', () => cvOut.value && copyText(cvOut.value));
$('#cv-swap').addEventListener('click', () => { cvIn.value = cvOut.value; cvRun(); });
const tsIn = $('#ts-in');
function tsRun() {
  const out = $('#ts-out'); out.replaceChildren();
  if (!tsIn.value.trim()) return;
  try { parseTime(tsIn.value).forEach(([k, v]) => out.append(el('dt', null, k), el('dd', null, v))); }
  catch (e) { out.append(el('dt', null, 'Hmm'), el('dd', null, e.message)); }
}
tsIn.addEventListener('input', debounce(tsRun, 150));
$('#ts-now').addEventListener('click', () => { tsIn.value = String(Math.floor(Date.now() / 1000)); tsRun(); });

/* ---------- JSON ---------- */
const jsIn = $('#js-in');
function jsValidate() {
  const status = $('#js-status');
  if (!jsIn.value.trim()) { setStatus(status, ''); return; }
  try { JSON.parse(jsIn.value); setStatus(status, 'Valid JSON · ' + jsIn.value.length.toLocaleString() + ' characters', 'ok'); }
  catch (e) { setStatus(status, jsonErrorMessage(jsIn.value, e), 'err'); }
}
function jsApply(fn) {
  try { jsIn.value = fn(jsIn.value); jsValidate(); } catch (e) { setStatus($('#js-status'), jsonErrorMessage(jsIn.value, e), 'err'); }
}
jsIn.addEventListener('input', debounce(jsValidate, 200));
$('#js-format').addEventListener('click', () => jsApply((t) => jsonFormat(t)));
$('#js-sort').addEventListener('click', () => jsApply((t) => jsonFormat(t, true)));
$('#js-min').addEventListener('click', () => jsApply(jsonMinify));
$('#js-copy').addEventListener('click', () => jsIn.value && copyText(jsIn.value));

/* ---------- Regex ---------- */
let worker = null;
function rxRun() {
  const status = $('#rx-status'), out = $('#rx-out');
  out.replaceChildren();
  const pattern = $('#rx-pat').value;
  if (!pattern) { setStatus(status, ''); return; }
  const text = $('#rx-text').value.slice(0, 50000);
  if (worker) worker.terminate();
  worker = new Worker('regex-worker.js');
  const timer = setTimeout(() => {
    worker.terminate();
    setStatus(status, 'That pattern took too long, so it was stopped. It may backtrack badly on this text.', 'err');
  }, 1500);
  worker.onmessage = (e) => {
    clearTimeout(timer);
    const r = e.data;
    if (!r.ok) { setStatus(status, r.error, 'err'); return; }
    setStatus(status, r.matches.length ? r.matches.length + (r.truncated ? '+' : '') + ' match(es)' : 'No matches', r.matches.length ? 'ok' : '');
    r.matches.slice(0, 50).forEach((m, i) => out.append(el('div', { class: 'check' },
      el('span', { class: 'lvl' }, '#' + (i + 1)),
      el('span', null, el('code', null, m.match === '' ? '(empty match)' : m.match), '  at ' + m.index,
        m.groups.length ? '  ·  groups: ' + m.groups.map((g) => (g === undefined ? '∅' : g)).join(' | ') : ''))));
  };
  worker.postMessage({ pattern, flags: $('#rx-flags').value, text });
}
['#rx-pat', '#rx-flags', '#rx-text'].forEach((s) => $(s).addEventListener('input', debounce(rxRun, 200)));

/* ---------- Burp proxy ---------- */
const BURP_DEFAULTS = { host: '127.0.0.1', port: 8080, enabled: false };
const BURP_BYPASS = ['<local>', 'localhost', '127.0.0.1', '[::1]', '*.localhost'];
let burp = { ...BURP_DEFAULTS };

function burpConfig(host, port) {
  return {
    mode: 'fixed_servers',
    rules: {
      singleProxy: { scheme: 'http', host, port },
      bypassList: BURP_BYPASS
    }
  };
}

function setBurpPill(kind, text) {
  const pill = $('#burp-pill');
  pill.className = 'proxy-pill' + (kind ? ' ' + kind : '');
  $('#burp-pill-text').textContent = text;
}

function readBurpForm() {
  const host = ($('#burp-host').value || '').trim() || BURP_DEFAULTS.host;
  const port = Number.parseInt($('#burp-port').value, 10);
  return { host, port };
}

function validBurp({ host, port }) {
  if (!host) return 'Enter a host (for example 127.0.0.1).';
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Port must be a number from 1 to 65535.';
  return '';
}

async function hasProxyPermission() {
  try { return await chrome.permissions.contains({ permissions: ['proxy'] }); }
  catch (e) { return false; }
}

async function ensureProxyPermission() {
  if (await hasProxyPermission()) return true;
  try { return await chrome.permissions.request({ permissions: ['proxy'] }); }
  catch (e) { return false; }
}

function proxyGet() {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.get({ incognito: false }, (details) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(details);
    });
  });
}

function proxySet(value) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.set({ value, scope: 'regular' }, () => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve();
    });
  });
}

function proxyClear() {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.clear({ scope: 'regular' }, () => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve();
    });
  });
}

async function syncBurpUi() {
  const status = $('#burp-status');
  const btn = $('#burp-toggle');
  $('#burp-host').value = burp.host || BURP_DEFAULTS.host;
  $('#burp-port').value = String(burp.port || BURP_DEFAULTS.port);

  const allowed = await hasProxyPermission();
  if (!allowed) {
    burp.enabled = false;
    setBurpPill('', 'Proxy off');
    btn.textContent = 'Use Burp';
    btn.classList.remove('danger');
    btn.classList.add('primary');
    setStatus(status, '');
    return;
  }

  let details;
  try { details = await proxyGet(); }
  catch (e) {
    setBurpPill('warn', 'Could not read proxy');
    setStatus(status, e.message, 'err');
    return;
  }

  const level = details.levelOfControl;
  const value = details.value || {};
  const rules = value.rules || {};
  const single = rules.singleProxy || rules.proxyForHttp || null;
  const onViaUs =
    value.mode === 'fixed_servers' &&
    level === 'controlled_by_this_extension' &&
    single &&
    single.host === burp.host &&
    Number(single.port) === Number(burp.port);

  // Keep stored flag honest if Chrome cleared our settings elsewhere.
  if (burp.enabled && level !== 'controlled_by_this_extension') {
    burp.enabled = false;
    await store.set('burp', burp);
  } else if (!burp.enabled && onViaUs) {
    burp.enabled = true;
    await store.set('burp', burp);
  }

  if (level === 'controlled_by_other_extensions') {
    setBurpPill('warn', 'Another extension controls the proxy');
    btn.textContent = 'Use Burp';
    btn.classList.add('primary');
    btn.classList.remove('danger');
    setStatus(status, 'Disable the other proxy extension, then try again.', 'err');
    return;
  }
  if (level === 'not_controllable') {
    setBurpPill('warn', 'Proxy not controllable');
    btn.textContent = 'Use Burp';
    btn.classList.add('primary');
    btn.classList.remove('danger');
    setStatus(status, 'Chrome policies prevent this extension from changing the proxy.', 'err');
    return;
  }

  if (burp.enabled || onViaUs) {
    setBurpPill('on', 'Proxy ON via Burp · ' + burp.host + ':' + burp.port);
    btn.textContent = 'Disable proxy';
    btn.classList.remove('primary');
    btn.classList.add('danger');
    setStatus(status, 'Browser traffic is routed through Burp. Turn it off when you finish testing.', 'ok');
  } else {
    setBurpPill('', 'Proxy off');
    btn.textContent = 'Use Burp';
    btn.classList.add('primary');
    btn.classList.remove('danger');
    setStatus(status, '');
  }
}

async function enableBurp() {
  const form = readBurpForm();
  const err = validBurp(form);
  if (err) { setStatus($('#burp-status'), err, 'err'); return; }
  if (!(await ensureProxyPermission())) {
    setStatus($('#burp-status'), 'Chrome needs the “proxy” permission to route traffic through Burp.', 'err');
    toast('Proxy permission declined');
    return;
  }
  try {
    await proxySet(burpConfig(form.host, form.port));
    burp = { host: form.host, port: form.port, enabled: true };
    await store.set('burp', burp);
    toast('Burp proxy enabled');
  } catch (e) {
    setStatus($('#burp-status'), 'Could not enable proxy: ' + e.message, 'err');
    return;
  }
  await syncBurpUi();
}

async function disableBurp() {
  if (!(await hasProxyPermission())) {
    burp.enabled = false;
    await store.set('burp', burp);
    await syncBurpUi();
    return;
  }
  try {
    await proxyClear();
    const form = readBurpForm();
    burp.enabled = false;
    if (!validBurp(form)) {
      burp.host = form.host;
      burp.port = form.port;
    }
    await store.set('burp', { host: burp.host, port: burp.port, enabled: false });
    toast('Proxy disabled');
  } catch (e) {
    setStatus($('#burp-status'), 'Could not disable proxy: ' + e.message, 'err');
    return;
  }
  await syncBurpUi();
}

$('#burp-toggle').addEventListener('click', async () => {
  if (burp.enabled) await disableBurp();
  else await enableBurp();
});

const saveBurpFields = debounce(async () => {
  const form = readBurpForm();
  if (validBurp(form)) return;
  burp.host = form.host;
  burp.port = form.port;
  await store.set('burp', { host: burp.host, port: burp.port, enabled: burp.enabled });
  // If proxy is already on, re-apply with the new host/port.
  if (burp.enabled && (await hasProxyPermission())) {
    try {
      await proxySet(burpConfig(form.host, form.port));
      await syncBurpUi();
    } catch (e) { setStatus($('#burp-status'), 'Could not update proxy: ' + e.message, 'err'); }
  }
}, 300);
$('#burp-host').addEventListener('input', saveBurpFields);
$('#burp-port').addEventListener('input', saveBurpFields);

/* ---------- Report ---------- */
const meta = { project: '', tester: '', scope: '' };
function renderReport() {
  const list = $('#rp-list');
  list.replaceChildren();
  const badge = $('#report-count');
  badge.hidden = !saved.length; badge.textContent = String(saved.length);
  if (!saved.length) {
    list.append(el('p', { class: 'empty' }, 'No findings yet. Scan a page or decode a JWT, then press "Add to report".'));
    return;
  }
  sortFindings(saved).forEach((f) => list.append(el('div', { class: 'rp-item sev-' + f.severity },
    el('span', { class: 'badge' }, SEV_LABEL[f.severity]), el('span', { class: 't', title: f.title }, f.title),
    el('button', { class: 'small ghost', 'aria-label': 'Remove ' + f.title, onclick: async () => {
      saved = saved.filter((s) => fid(s) !== fid(f)); await store.set('findings', saved); renderReport();
    } }, '×'))));
}
[['project', '#rp-project'], ['tester', '#rp-tester'], ['scope', '#rp-scope']].forEach(([k, s]) => {
  $(s).addEventListener('input', () => { meta[k] = $(s).value; store.set('meta', meta); });
});
function needFindings() { if (!saved.length) { toast('Add at least one finding first'); return false; } return true; }
const stamp = () => new Date().toISOString().slice(0, 10);
$('#rp-md').addEventListener('click', () => needFindings() && download('security-findings-' + stamp() + '.md', toMarkdown(meta, saved), 'text/markdown'));
$('#rp-html').addEventListener('click', () => needFindings() && download('security-findings-' + stamp() + '.html', toHtml(meta, saved), 'text/html'));
$('#rp-copy').addEventListener('click', () => needFindings() && copyText(toMarkdown(meta, saved), 'Markdown copied'));
$('#rp-clear').addEventListener('click', async () => {
  if (!saved.length) return;
  if (!confirm('Remove all ' + saved.length + ' findings from the report?')) return;
  saved = []; await store.set('findings', saved); renderReport();
});

/* ---------- Network monitoring ---------- */
const NET_HOSTS = ['http://*/*', 'https://*/*'];
const netUi = {
  enabled: false,
  paused: false,
  listening: false,
  entries: [],
  selectedId: null,
  filter: '',
  method: '',
  tabId: null
};

function netMsg(type, extra) {
  return chrome.runtime.sendMessage({ type, ...(extra || {}) });
}

async function hasNetPermission() {
  try {
    return await chrome.permissions.contains({
      permissions: ['webRequest'],
      origins: NET_HOSTS
    });
  } catch (e) { return false; }
}

async function ensureNetPermission() {
  if (await hasNetPermission()) return true;
  try {
    return await chrome.permissions.request({
      permissions: ['webRequest'],
      origins: NET_HOSTS
    });
  } catch (e) { return false; }
}

function formatBytes(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10 * 1024 ? 1 : 0) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatDuration(ms) {
  if (ms == null || !Number.isFinite(ms)) return '—';
  if (ms < 1000) return ms + ' ms';
  return (ms / 1000).toFixed(2) + ' s';
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname + u.search + u.hash || '/';
  } catch (e) {
    return url || '';
  }
}

function statusClass(entry) {
  if (entry.error) return 'err';
  if (entry.statusCode == null) return 'pending';
  const c = entry.statusCode;
  if (c >= 200 && c < 300) return 'ok';
  if (c >= 300 && c < 400) return 'redirect';
  if (c >= 400 && c < 500) return 'client';
  if (c >= 500) return 'server';
  return '';
}

function statusText(entry) {
  if (entry.error) return 'ERR';
  if (entry.statusCode == null) return '…';
  return String(entry.statusCode);
}

function entrySize(entry) {
  if (entry.responseSize != null) return entry.responseSize;
  if (entry.requestBodySize != null) return entry.requestBodySize;
  return null;
}

function headersBlock(list) {
  if (!list || !list.length) return '(none captured)';
  return list.map((h) => h.name + ': ' + h.value).join('\n');
}

function netFiltered() {
  const q = (netUi.filter || '').trim().toLowerCase();
  const method = (netUi.method || '').toUpperCase();
  return netUi.entries.filter((e) => {
    if (method && e.method !== method) return false;
    if (q && !(e.url || '').toLowerCase().includes(q)) return false;
    return true;
  });
}

function setNetPill() {
  const pill = $('#net-pill');
  const text = $('#net-pill-text');
  pill.className = 'proxy-pill';
  if (!netUi.enabled) {
    text.textContent = 'Monitoring off';
  } else if (netUi.paused) {
    pill.classList.add('warn');
    text.textContent = 'Paused · active tab only';
  } else if (netUi.listening) {
    pill.classList.add('on');
    text.textContent = 'Live · active tab';
  } else {
    pill.classList.add('warn');
    text.textContent = 'Permission needed';
  }
}

function syncNetControls() {
  const toggle = $('#net-toggle');
  const pause = $('#net-pause');
  const clear = $('#net-clear');
  toggle.textContent = netUi.enabled ? 'Stop monitoring' : 'Start monitoring';
  pause.disabled = !netUi.enabled;
  pause.textContent = netUi.paused ? 'Resume' : 'Pause';
  clear.disabled = !netUi.enabled && !netUi.entries.length;
  setNetPill();
  const badge = $('#net-count');
  const n = netFiltered().length;
  badge.hidden = !n;
  badge.textContent = String(n);
}

function renderNetDetail(entry) {
  const box = $('#net-detail');
  if (!entry) { box.hidden = true; box.replaceChildren(); return; }
  box.hidden = false;
  box.replaceChildren(
    el('h3', null, entry.method + ' · ' + (entry.type || 'other')),
    el('div', { class: 'net-url' }, entry.url || ''),
    el('dl', { class: 'kv' },
      el('dt', null, 'Status'), el('dd', null, entry.error ? entry.error : (entry.statusCode != null ? String(entry.statusCode) : 'pending') + (entry.statusLine ? ' · ' + entry.statusLine : '')),
      el('dt', null, 'Time'), el('dd', null, formatDuration(entry.duration)),
      el('dt', null, 'Response size'), el('dd', null, formatBytes(entry.responseSize) + (entry.fromCache ? ' (cache)' : '')),
      el('dt', null, 'Request size'), el('dd', null, formatBytes(entry.requestBodySize)),
      el('dt', null, 'Content-Type'), el('dd', null, entry.contentType || '—'),
      el('dt', null, 'Initiator'), el('dd', null, entry.initiator || '—'),
      el('dt', null, 'Remote IP'), el('dd', null, entry.ip || '—')
    ),
    el('div', { class: 'sec' }, 'Request headers'),
    el('pre', { class: 'net-headers' }, headersBlock(entry.requestHeaders)),
    el('div', { class: 'sec' }, 'Response headers'),
    el('pre', { class: 'net-headers' }, headersBlock(entry.responseHeaders)),
    el('p', { class: 'hint' }, 'Bodies are not available via webRequest in Manifest V3. Use Burp for full intercept.')
  );
}

function renderNetList() {
  const box = $('#net-list');
  const rows = netFiltered();
  const prevScroll = box.scrollTop;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 28;
  box.replaceChildren();
  if (!rows.length) {
    const msg = !netUi.enabled
      ? 'Press Start monitoring to capture requests for the active tab.'
      : netUi.entries.length
        ? 'No requests match this filter.'
        : (netUi.paused ? 'Paused. Resume to capture new requests.' : 'Waiting for requests on the active tab…');
    box.append(el('div', { class: 'net-empty' }, msg));
    renderNetDetail(null);
    syncNetControls();
    return;
  }
  const frag = document.createDocumentFragment();
  rows.forEach((entry) => {
    const row = el('div', {
      class: 'net-row' + (entry.id === netUi.selectedId ? ' selected' : ''),
      role: 'listitem',
      title: entry.url,
      onclick: () => {
        netUi.selectedId = entry.id;
        renderNetList();
      }
    },
      el('span', { class: 'm' }, entry.method),
      el('span', { class: 'st ' + statusClass(entry) }, statusText(entry)),
      el('span', { class: 'url' }, shortUrl(entry.url)),
      el('span', { class: 'ty' }, entry.type || ''),
      el('span', { class: 'tm' }, formatDuration(entry.duration)),
      el('span', { class: 'sz' }, formatBytes(entrySize(entry)))
    );
    frag.append(row);
  });
  box.append(frag);
  const selected = rows.find((e) => e.id === netUi.selectedId) || null;
  if (!selected) netUi.selectedId = null;
  renderNetDetail(selected);
  if ($('#net-autoscroll').checked && atBottom) box.scrollTop = box.scrollHeight;
  else box.scrollTop = prevScroll;
  syncNetControls();
}

function upsertNetEntry(entry) {
  if (!entry || entry.tabId !== netUi.tabId) return;
  const i = netUi.entries.findIndex((e) => e.id === entry.id);
  if (i >= 0) netUi.entries[i] = entry;
  else netUi.entries.push(entry);
  while (netUi.entries.length > 150) netUi.entries.shift();
  renderNetList();
}

async function refreshNetTabId() {
  const tab = await currentTab();
  const id = tab && tab.id != null ? tab.id : null;
  if (id !== netUi.tabId) {
    netUi.tabId = id;
    netUi.selectedId = null;
    return true;
  }
  return false;
}

async function loadNetList() {
  await refreshNetTabId();
  if (netUi.tabId == null) {
    netUi.entries = [];
    renderNetList();
    setStatus($('#net-status'), 'Could not find the active browser tab.', 'err');
    return;
  }
  try {
    const res = await netMsg('netMon:list', { tabId: netUi.tabId });
    if (res && res.ok) {
      netUi.enabled = !!res.enabled;
      netUi.paused = !!res.paused;
      netUi.listening = !!res.listening;
      netUi.entries = Array.isArray(res.entries) ? res.entries.slice() : [];
    }
  } catch (e) {
    netUi.entries = [];
  }
  renderNetList();
}

async function syncNetUi() {
  try {
    const res = await netMsg('netMon:getState');
    if (res && res.ok) {
      netUi.enabled = !!res.enabled;
      netUi.paused = !!res.paused;
      netUi.listening = !!res.listening;
    }
  } catch (e) { /* SW waking */ }
  syncNetControls();
  if (netUi.enabled) await loadNetList();
  else {
    netUi.entries = [];
    renderNetList();
    setStatus($('#net-status'), '');
  }
}

$('#net-toggle').addEventListener('click', async () => {
  const status = $('#net-status');
  if (netUi.enabled) {
    try { await netMsg('netMon:stop'); } catch (e) { /* ignore */ }
    netUi.enabled = false;
    netUi.paused = false;
    netUi.listening = false;
    setStatus(status, 'Monitoring stopped. Captured rows stay until you Clear.', 'ok');
    syncNetControls();
    toast('Network monitoring stopped');
    return;
  }
  setStatus(status, 'Chrome will ask for permission to observe http(s) requests…');
  if (!(await ensureNetPermission())) {
    setStatus(status, 'Chrome needs webRequest and site access to show network traffic.', 'err');
    toast('Network permission declined');
    return;
  }
  try {
    const res = await netMsg('netMon:start');
    if (!res || !res.ok) {
      setStatus(status, (res && res.error) || 'Could not start monitoring. Reload the extension and try again.', 'err');
      return;
    }
    netUi.enabled = true;
    netUi.paused = false;
    netUi.listening = !!res.listening;
    if (!netUi.listening) {
      setStatus(status, 'Permission granted, but listeners did not attach. Press Stop, then Start again — or reload the extension.', 'err');
    } else {
      setStatus(status, 'Listening for requests on the active tab. Click a row for headers and timing.', 'ok');
      toast('Network monitoring on');
    }
    await loadNetList();
  } catch (e) {
    setStatus(status, 'Could not start monitoring: ' + (e && e.message ? e.message : e), 'err');
  }
  syncNetControls();
});

$('#net-pause').addEventListener('click', async () => {
  if (!netUi.enabled) return;
  try {
    const res = await netMsg(netUi.paused ? 'netMon:resume' : 'netMon:pause');
    if (res && res.ok) {
      netUi.paused = !!res.paused;
      setStatus($('#net-status'), netUi.paused ? 'Paused — new requests are not captured.' : 'Live again.', netUi.paused ? '' : 'ok');
      syncNetControls();
      renderNetList();
    }
  } catch (e) {
    setStatus($('#net-status'), 'Could not update pause state.', 'err');
  }
});

$('#net-clear').addEventListener('click', async () => {
  await refreshNetTabId();
  try { await netMsg('netMon:clear', { tabId: netUi.tabId }); } catch (e) { /* ignore */ }
  netUi.entries = [];
  netUi.selectedId = null;
  renderNetList();
  setStatus($('#net-status'), 'Cleared requests for this tab.', 'ok');
});

$('#net-filter').addEventListener('input', debounce(() => {
  netUi.filter = $('#net-filter').value || '';
  renderNetList();
}, 120));
$('#net-method').addEventListener('change', () => {
  netUi.method = $('#net-method').value || '';
  renderNetList();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'netMon:state') {
    netUi.enabled = !!msg.enabled;
    netUi.paused = !!msg.paused;
    netUi.listening = !!msg.listening;
    syncNetControls();
    return;
  }
  if (msg.type === 'netMon:cleared') {
    if (msg.tabId == null || msg.tabId === netUi.tabId) {
      netUi.entries = [];
      netUi.selectedId = null;
      renderNetList();
    }
    return;
  }
  if (msg.type === 'netMon:entry' && msg.entry) {
    upsertNetEntry(msg.entry);
  }
});

chrome.tabs.onActivated.addListener(async () => {
  if ($('#p-network').hidden) return;
  const changed = await refreshNetTabId();
  if (changed) await loadNetList();
});

chrome.tabs.onUpdated.addListener(async (tabId, info) => {
  if ($('#p-network').hidden) return;
  if (tabId === netUi.tabId && (info.url || info.status === 'loading')) {
    // Keep watching the same tab; list already streams live updates.
  }
});

/* ---------- Init ---------- */
(async function init() {
  saved = await store.get('findings', []);
  Object.assign(meta, await store.get('meta', {}));
  Object.assign(burp, await store.get('burp', BURP_DEFAULTS));
  $('#rp-project').value = meta.project || ''; $('#rp-tester').value = meta.tester || ''; $('#rp-scope').value = meta.scope || '';
  renderReport();
  await syncBurpUi();
  await syncNetUi();
  const tab = await currentTab();
  if (isWeb(tab)) {
    state.tab = tab;
    try { $('#site').textContent = new URL(tabUrl(tab)).hostname; }
    catch (e) { $('#site').textContent = 'Ready when you are'; }
  } else {
    const url = tabUrl(tab);
    $('#site').textContent = url && (/^chrome:\/\//i.test(url) || /^chrome-extension:\/\//i.test(url))
      ? 'Switch to a website tab'
      : 'Open a website to scan it';
  }
})();
