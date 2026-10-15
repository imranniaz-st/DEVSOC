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

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}
const isWeb = (tab) => tab && /^https?:/i.test(tab.url || '');

async function runScan() {
  const status = $('#scan-status'), btn = $('#scan-btn');
  setStatus(status, '');
  const tab = await currentTab();
  if (!isWeb(tab)) {
    setStatus(status, 'Open a regular website (http or https) and try again. Chrome does not let extensions run on its own pages or the Web Store.', 'err');
    return;
  }
  state.tab = tab;
  btn.disabled = true; btn.textContent = 'Scanning…';
  setStatus(status, 'Reading the page and its scripts…');
  try {
    const [{ result: data }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPageData });
    let globals = [];
    try {
      const [g] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, world: 'MAIN', func: detectGlobals });
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

/* ---------- Init ---------- */
(async function init() {
  saved = await store.get('findings', []);
  Object.assign(meta, await store.get('meta', {}));
  $('#rp-project').value = meta.project || ''; $('#rp-tester').value = meta.tester || ''; $('#rp-scope').value = meta.scope || '';
  renderReport();
  const tab = await currentTab();
  if (isWeb(tab)) { state.tab = tab; $('#site').textContent = new URL(tab.url).hostname; }
  else $('#site').textContent = 'Open a website to scan it';
})();
