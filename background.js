// Opens the friendly welcome page once, right after install.
// Toolbar icon opens the side panel (not a popup).
// Optional Network Monitoring uses webRequest when the user enables it.

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') });
  }
});

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

/* ---------- Network monitoring (optional webRequest) ---------- */
const NET_MAX = 150;
const NET_FILTER = { urls: ['http://*/*', 'https://*/*'] };
const netBuffers = new Map(); // tabId -> entry[]
const netInflight = new Map(); // requestId -> entry
let netListening = false;
let netEnabled = false;
let netPaused = false;

function netDefaults() {
  return { enabled: false, paused: false };
}

async function netLoadState() {
  try {
    const r = await chrome.storage.local.get({ netMon: netDefaults() });
    const s = r.netMon || netDefaults();
    netEnabled = !!s.enabled;
    netPaused = !!s.paused;
  } catch (e) {
    netEnabled = false;
    netPaused = false;
  }
  if (netEnabled) netAttach();
  else netDetach();
}

async function netSaveState() {
  await chrome.storage.local.set({ netMon: { enabled: netEnabled, paused: netPaused } });
}

function netCanListen() {
  return typeof chrome.webRequest !== 'undefined' && !!chrome.webRequest.onBeforeRequest;
}

function headerList(headers) {
  if (!headers || !headers.length) return [];
  return headers.map((h) => ({ name: h.name, value: h.value != null ? String(h.value) : '' }));
}

function findHeader(headers, name) {
  const want = name.toLowerCase();
  for (const h of headers || []) {
    if (h.name && h.name.toLowerCase() === want) return h.value || '';
  }
  return '';
}

function requestBodySize(requestBody) {
  if (!requestBody) return null;
  if (requestBody.raw && requestBody.raw.length) {
    let n = 0;
    for (const part of requestBody.raw) {
      if (part.bytes) n += part.bytes.byteLength;
    }
    return n;
  }
  if (requestBody.formData) {
    let n = 0;
    for (const [k, vals] of Object.entries(requestBody.formData)) {
      n += k.length;
      for (const v of vals) n += String(v).length;
    }
    return n;
  }
  return null;
}

function parseContentLength(headers) {
  const raw = findHeader(headers, 'content-length');
  if (!raw) return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : null;
}

function bufferFor(tabId) {
  let list = netBuffers.get(tabId);
  if (!list) {
    list = [];
    netBuffers.set(tabId, list);
  }
  return list;
}

function pushEntry(entry) {
  if (entry.tabId < 0) return;
  const list = bufferFor(entry.tabId);
  list.push(entry);
  while (list.length > NET_MAX) list.shift();
  netBroadcast({ type: 'netMon:entry', entry });
}

function updateEntry(entry) {
  netBroadcast({ type: 'netMon:entry', entry, update: true });
}

function netBroadcast(msg) {
  try {
    chrome.runtime.sendMessage(msg).catch(() => {});
  } catch (e) { /* no receivers */ }
}

function shouldIgnore(details) {
  if (details.tabId == null || details.tabId < 0) return true;
  const url = details.url || '';
  if (url.startsWith('chrome-extension://') || url.startsWith('chrome://')) return true;
  return false;
}

function ensureEntry(details, extras) {
  let entry = netInflight.get(details.requestId);
  if (!entry) {
    entry = {
      id: details.requestId,
      tabId: details.tabId,
      url: details.url || '',
      method: (details.method || 'GET').toUpperCase(),
      type: details.type || 'other',
      statusCode: null,
      statusLine: '',
      fromCache: false,
      error: '',
      startTime: details.timeStamp || Date.now(),
      endTime: null,
      duration: null,
      requestHeaders: [],
      responseHeaders: [],
      requestBodySize: null,
      responseSize: null,
      contentType: '',
      initiator: details.initiator || '',
      ip: '',
      completed: false
    };
    netInflight.set(details.requestId, entry);
    pushEntry(entry);
  }
  if (extras) Object.assign(entry, extras);
  return entry;
}

function netTrackable(details) {
  if (!netEnabled || shouldIgnore(details)) return false;
  // While paused, only finish requests already in flight — do not start new rows.
  if (netPaused && !netInflight.has(details.requestId)) return false;
  return true;
}

function onBeforeRequest(details) {
  if (!netEnabled || shouldIgnore(details)) return;
  if (netPaused) return;
  const entry = ensureEntry(details, {
    url: details.url,
    method: (details.method || 'GET').toUpperCase(),
    type: details.type || 'other',
    initiator: details.initiator || '',
    requestBodySize: requestBodySize(details.requestBody)
  });
  updateEntry(entry);
}

function onSendHeaders(details) {
  if (!netTrackable(details)) return;
  const entry = ensureEntry(details, {
    requestHeaders: headerList(details.requestHeaders)
  });
  updateEntry(entry);
}

function onHeadersReceived(details) {
  if (!netTrackable(details)) return;
  const responseHeaders = headerList(details.responseHeaders);
  const entry = ensureEntry(details, {
    statusCode: details.statusCode != null ? details.statusCode : null,
    statusLine: details.statusLine || '',
    responseHeaders,
    responseSize: parseContentLength(responseHeaders),
    contentType: findHeader(responseHeaders, 'content-type')
  });
  updateEntry(entry);
}

function onCompleted(details) {
  if (!netTrackable(details)) return;
  const responseHeaders = details.responseHeaders ? headerList(details.responseHeaders) : null;
  const entry = ensureEntry(details, {
    statusCode: details.statusCode != null ? details.statusCode : null,
    statusLine: details.statusLine || '',
    fromCache: !!details.fromCache,
    ip: details.ip || '',
    endTime: details.timeStamp || Date.now(),
    completed: true
  });
  if (responseHeaders) {
    entry.responseHeaders = responseHeaders;
    if (entry.responseSize == null) entry.responseSize = parseContentLength(responseHeaders);
    if (!entry.contentType) entry.contentType = findHeader(responseHeaders, 'content-type');
  }
  entry.duration = entry.endTime != null && entry.startTime != null
    ? Math.max(0, Math.round(entry.endTime - entry.startTime))
    : null;
  netInflight.delete(details.requestId);
  updateEntry(entry);
}

function onErrorOccurred(details) {
  if (!netTrackable(details)) return;
  const entry = ensureEntry(details, {
    error: details.error || 'net::ERR',
    endTime: details.timeStamp || Date.now(),
    completed: true
  });
  entry.duration = entry.endTime != null && entry.startTime != null
    ? Math.max(0, Math.round(entry.endTime - entry.startTime))
    : null;
  netInflight.delete(details.requestId);
  updateEntry(entry);
}

function netAttach() {
  if (netListening || !netCanListen()) return;
  try {
    chrome.webRequest.onBeforeRequest.addListener(onBeforeRequest, NET_FILTER, ['requestBody']);
    chrome.webRequest.onSendHeaders.addListener(onSendHeaders, NET_FILTER, ['requestHeaders', 'extraHeaders']);
    chrome.webRequest.onHeadersReceived.addListener(onHeadersReceived, NET_FILTER, ['responseHeaders', 'extraHeaders']);
    chrome.webRequest.onCompleted.addListener(onCompleted, NET_FILTER, ['responseHeaders', 'extraHeaders']);
    chrome.webRequest.onErrorOccurred.addListener(onErrorOccurred, NET_FILTER);
    netListening = true;
  } catch (e) {
    netListening = false;
  }
}

function netDetach() {
  if (!netListening || !netCanListen()) {
    netListening = false;
    return;
  }
  try {
    chrome.webRequest.onBeforeRequest.removeListener(onBeforeRequest);
    chrome.webRequest.onSendHeaders.removeListener(onSendHeaders);
    chrome.webRequest.onHeadersReceived.removeListener(onHeadersReceived);
    chrome.webRequest.onCompleted.removeListener(onCompleted);
    chrome.webRequest.onErrorOccurred.removeListener(onErrorOccurred);
  } catch (e) { /* already gone */ }
  netListening = false;
}

function netClearTab(tabId) {
  if (tabId == null) {
    netBuffers.clear();
    netInflight.clear();
    return;
  }
  netBuffers.delete(tabId);
  for (const [rid, entry] of netInflight) {
    if (entry.tabId === tabId) netInflight.delete(rid);
  }
}

function netSnapshot(tabId) {
  if (tabId == null) return [];
  return (netBuffers.get(tabId) || []).slice();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type || !String(msg.type).startsWith('netMon:')) return;

  (async () => {
    if (msg.type === 'netMon:getState') {
      sendResponse({
        ok: true,
        enabled: netEnabled,
        paused: netPaused,
        listening: netListening && netCanListen(),
        hasApi: netCanListen()
      });
      return;
    }

    if (msg.type === 'netMon:start') {
      if (!netCanListen()) {
        sendResponse({ ok: false, error: 'webRequest permission not available' });
        return;
      }
      netEnabled = true;
      netPaused = false;
      netAttach();
      await netSaveState();
      netBroadcast({ type: 'netMon:state', enabled: true, paused: false, listening: netListening });
      sendResponse({ ok: true, enabled: true, paused: false, listening: netListening });
      return;
    }

    if (msg.type === 'netMon:stop') {
      netEnabled = false;
      netPaused = false;
      netDetach();
      await netSaveState();
      netBroadcast({ type: 'netMon:state', enabled: false, paused: false, listening: false });
      sendResponse({ ok: true, enabled: false, paused: false, listening: false });
      return;
    }

    if (msg.type === 'netMon:pause') {
      netPaused = true;
      await netSaveState();
      netBroadcast({ type: 'netMon:state', enabled: netEnabled, paused: true, listening: netListening });
      sendResponse({ ok: true, enabled: netEnabled, paused: true });
      return;
    }

    if (msg.type === 'netMon:resume') {
      netPaused = false;
      await netSaveState();
      netBroadcast({ type: 'netMon:state', enabled: netEnabled, paused: false, listening: netListening });
      sendResponse({ ok: true, enabled: netEnabled, paused: false });
      return;
    }

    if (msg.type === 'netMon:clear') {
      netClearTab(msg.tabId);
      netBroadcast({ type: 'netMon:cleared', tabId: msg.tabId });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === 'netMon:list') {
      sendResponse({
        ok: true,
        enabled: netEnabled,
        paused: netPaused,
        listening: netListening && netCanListen(),
        entries: netSnapshot(msg.tabId)
      });
      return;
    }

    sendResponse({ ok: false, error: 'unknown netMon message' });
  })();

  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  netClearTab(tabId);
});

netLoadState();
