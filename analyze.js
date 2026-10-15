// Turns raw page data into plain-language findings. Pure functions: no network, no DOM.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const PENALTY = { critical: 30, high: 20, medium: 10, low: 4, info: 0 };

const F = (category, severity, title, detail, fix, evidence = '') => ({ category, severity, title, detail, fix, evidence });

export function parseCsp(csp) {
  const out = {};
  String(csp).split(';').forEach((part) => {
    const bits = part.trim().split(/\s+/).filter(Boolean);
    if (bits.length) out[bits[0].toLowerCase()] = bits.slice(1);
  });
  return out;
}

export function compareVersions(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function analyzeHeaders(headers, https) {
  const f = [];
  if (!headers) return f;
  const h = {};
  Object.keys(headers).forEach((k) => { h[k.toLowerCase()] = String(headers[k]); });

  const csp = h['content-security-policy'];
  const cspMap = csp ? parseCsp(csp) : null;
  if (!csp) {
    f.push(F('Headers', 'medium', 'No Content-Security-Policy header',
      'The page does not tell the browser which scripts and resources are allowed to load. If an attacker finds an XSS bug, it is much easier to exploit.',
      "Send a Content-Security-Policy header. A good start is: default-src 'self'; then loosen only what you need."));
  } else {
    const script = cspMap['script-src'] || cspMap['default-src'] || [];
    const hasNonce = script.some((x) => /^'(nonce-|sha(256|384|512)-)/.test(x));
    if (script.includes("'unsafe-inline'") && !hasNonce) {
      f.push(F('Headers', 'low', "CSP allows 'unsafe-inline' scripts",
        'Inline scripts are allowed, which removes most of the protection CSP gives against XSS.',
        "Move inline scripts to files, or use nonces/hashes instead of 'unsafe-inline'.", csp.slice(0, 300)));
    }
    if (script.includes("'unsafe-eval'")) {
      f.push(F('Headers', 'low', "CSP allows 'unsafe-eval'",
        'eval() and similar functions are allowed, which gives attackers an easy way to run injected code.',
        "Remove 'unsafe-eval' and avoid eval/new Function in your code.", csp.slice(0, 300)));
    }
    if (script.some((x) => x === '*' || x === 'https:' || x === 'http:' || x === 'data:')) {
      f.push(F('Headers', 'low', 'CSP script-src is very broad',
        'A wildcard or whole-scheme source lets scripts load from almost anywhere.',
        'List the exact hosts you trust instead of * or a whole scheme.', csp.slice(0, 300)));
    }
  }

  if (https) {
    const hsts = h['strict-transport-security'];
    if (!hsts) {
      f.push(F('Headers', 'medium', 'No Strict-Transport-Security (HSTS) header',
        'Browsers are not told to always use HTTPS for this site, so a visitor on a hostile network could be downgraded to HTTP.',
        'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains'));
    } else {
      const m = /max-age=(\d+)/i.exec(hsts);
      if (!m || parseInt(m[1], 10) < 15552000) {
        f.push(F('Headers', 'low', 'HSTS max-age is short',
          'HSTS is on, but it expires in under 180 days, which weakens the protection.',
          'Raise max-age to at least 31536000 (one year).', hsts));
      }
    }
  }

  const xfo = h['x-frame-options'];
  const fa = cspMap && cspMap['frame-ancestors'];
  if (!xfo && !fa) {
    f.push(F('Headers', 'low', 'No clickjacking protection',
      'Other sites can embed this page in a frame and trick people into clicking things they cannot see.',
      "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY."));
  }

  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    f.push(F('Headers', 'low', 'Missing X-Content-Type-Options: nosniff',
      'Browsers may guess file types, which can turn an uploaded file into runnable script.',
      'Send: X-Content-Type-Options: nosniff'));
  }

  if (!h['referrer-policy']) {
    f.push(F('Headers', 'info', 'No Referrer-Policy header',
      'Without an explicit policy, the browser default decides how much of your URLs are shared with other sites.',
      'Send: Referrer-Policy: strict-origin-when-cross-origin'));
  }
  if (!h['permissions-policy']) {
    f.push(F('Headers', 'info', 'No Permissions-Policy header',
      'Powerful browser features (camera, microphone, geolocation) are not explicitly restricted.',
      'Send a Permissions-Policy header that disables features you do not use, e.g. camera=(), microphone=(), geolocation=()'));
  }

  const server = h['server'];
  if (server && /\d+\.\d+/.test(server)) {
    f.push(F('Information leak', 'low', 'Server version is visible',
      'Exact software versions help attackers look up known vulnerabilities.',
      'Hide or trim the Server header in your web server or CDN settings.', 'Server: ' + server));
  }
  ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'].forEach((name) => {
    if (h[name]) {
      f.push(F('Information leak', 'low', 'Technology is advertised in ' + name,
        'This header tells everyone which framework or runtime you use.',
        'Remove the ' + name + ' header.', name + ': ' + h[name]));
    }
  });

  const acao = h['access-control-allow-origin'];
  const acac = (h['access-control-allow-credentials'] || '').toLowerCase();
  if (acao === '*' && acac === 'true') {
    f.push(F('CORS', 'high', 'CORS allows any origin together with credentials',
      'Browsers block this combination, but it shows the CORS setup is misconfigured and may be reflecting origins elsewhere.',
      'Return a specific, allow-listed origin and never combine * with credentials.',
      'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true'));
  } else if (acao === 'null') {
    f.push(F('CORS', 'medium', 'CORS trusts the "null" origin',
      'Sandboxed iframes and local files send Origin: null, so attackers can use it to read responses.',
      'Remove "null" from the allowed origins.', 'Access-Control-Allow-Origin: null'));
  } else if (acao === '*') {
    f.push(F('CORS', 'info', 'CORS is open to any origin',
      'Any website can read this response. That is fine for public data, but not for anything private.',
      'Confirm this resource is meant to be public.', 'Access-Control-Allow-Origin: *'));
  }
  return f;
}

const SESSIONISH = /(sess|sid|token|auth|jwt|login|csrf|xsrf)/i;

export function analyzeCookies(cookies, https) {
  const f = [];
  if (!Array.isArray(cookies) || !cookies.length) return f;
  const names = (list) => list.map((c) => c.name).slice(0, 12).join(', ') + (list.length > 12 ? ' …' : '');

  const noSecure = cookies.filter((c) => !c.secure);
  if (https && noSecure.length) {
    f.push(F('Cookies', 'medium', noSecure.length + ' cookie(s) missing the Secure flag',
      'These cookies can also be sent over plain HTTP, where anyone on the network can read them.',
      'Set the Secure attribute on every cookie.', names(noSecure)));
  }
  const noHttpOnly = cookies.filter((c) => !c.httpOnly && SESSIONISH.test(c.name));
  if (noHttpOnly.length) {
    f.push(F('Cookies', 'medium', noHttpOnly.length + ' session-like cookie(s) readable by JavaScript',
      'Without HttpOnly, any XSS bug can steal these cookies.',
      'Set the HttpOnly attribute on session and auth cookies.', names(noHttpOnly)));
  }
  const none = cookies.filter((c) => c.sameSite === 'no_restriction');
  if (none.length) {
    f.push(F('Cookies', none.some((c) => !c.secure) ? 'medium' : 'low', none.length + ' cookie(s) use SameSite=None',
      'These cookies are sent on cross-site requests, which makes cross-site request forgery easier.',
      'Use SameSite=Lax or Strict unless you really need cross-site cookies (and then add Secure).', names(none)));
  }
  const unspecified = cookies.filter((c) => c.sameSite === 'unspecified');
  if (unspecified.length) {
    f.push(F('Cookies', 'info', unspecified.length + ' cookie(s) without a SameSite attribute',
      'Chrome treats these as Lax, but other browsers may not.',
      'Set SameSite explicitly.', names(unspecified)));
  }
  const yearAhead = Date.now() / 1000 + 365 * 86400;
  const longLived = cookies.filter((c) => c.expirationDate && c.expirationDate > yearAhead && SESSIONISH.test(c.name));
  if (longLived.length) {
    f.push(F('Cookies', 'low', longLived.length + ' session-like cookie(s) live over a year',
      'Long-lived session cookies give a stolen cookie a very long useful life.',
      'Use shorter lifetimes and rotate session IDs.', names(longLived)));
  }
  return f;
}

const SECRET_SEVERITY = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

export function analyzePage(d) {
  const f = [];
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(d.hostname);

  if (!d.https && !local) {
    f.push(F('Transport', 'high', 'Page is served over HTTP',
      'Everything on this page, including logins and cookies, travels unencrypted and can be read or changed on the network.',
      'Serve the whole site over HTTPS and redirect HTTP to HTTPS.', d.url));
  }

  if (d.headerError) {
    f.push(F('Headers', 'info', 'Could not read response headers',
      'The page blocked the header check, so header findings are missing.',
      'Try again after reloading the page.', d.headerError));
  }
  f.push(...analyzeHeaders(d.headers, d.https));

  if (d.mixed && d.mixed.length) {
    f.push(F('Transport', 'medium', d.mixed.length + ' insecure (HTTP) resource(s) on an HTTPS page',
      'Mixed content can be tampered with on the network and weakens the whole page.',
      'Load every resource over HTTPS.', d.mixed.slice(0, 6).join('\n')));
  }
  if (d.forms) {
    const pw = d.forms.filter((x) => x.hasPassword);
    if (!d.https && !local && pw.length) {
      f.push(F('Transport', 'high', 'Password field on an insecure page',
        'Passwords typed here are sent without encryption.', 'Serve this page over HTTPS.', d.url));
    }
    const bad = d.forms.filter((x) => x.insecureAction);
    if (bad.length) {
      f.push(F('Transport', 'medium', bad.length + ' form(s) submit to an HTTP address',
        'Form data is sent unencrypted even though the page uses HTTPS.',
        'Change each form action to an https:// URL.', bad.map((x) => x.action).slice(0, 5).join('\n')));
    }
  }
  if (d.noSri && d.noSri.length) {
    f.push(F('Third-party code', 'low', d.noSri.length + ' third-party script(s) without Subresource Integrity',
      'If the other site is hacked, its script runs on your page with full access.',
      'Add integrity="sha384-…" and crossorigin="anonymous" to third-party script tags, or host the files yourself.',
      d.noSri.slice(0, 6).join('\n')));
  }
  if (d.blankLinks > 0) {
    f.push(F('Links', 'info', d.blankLinks + ' link(s) open a new tab without rel="noopener"',
      'Modern browsers handle this safely, but older ones let the new tab control this page.',
      'Add rel="noopener noreferrer" to links with target="_blank".'));
  }

  (d.secrets || []).forEach((s) => {
    f.push(F('Exposed secrets', SECRET_SEVERITY[s.severity] || 'medium', s.type + ' found in page code',
      s.note || 'A value that looks like a real credential is visible to every visitor. Treat it as public and rotate it if it is a real secret.',
      'Remove it from client-side code, rotate the credential, and keep secrets on the server.',
      s.masked + '\nFound in: ' + s.source));
  });
  if (d.tokens && d.tokens.length) {
    f.push(F('Exposed secrets', 'low', d.tokens.length + ' JWT-like token(s) found in the page',
      'Tokens in page code, web storage, or JavaScript-readable cookies can be stolen by any XSS bug. Use the JWT tab to inspect them.',
      'Prefer HttpOnly cookies for session tokens and keep token lifetimes short.',
      d.tokens.map((t) => t.where + ': ' + t.masked).slice(0, 6).join('\n')));
  }
  if (d.storageKeys && d.storageKeys.length) {
    f.push(F('Storage', 'low', 'Sensitive-looking keys in browser storage',
      'Anything in localStorage or sessionStorage can be read by any script on the page.',
      'Keep auth tokens in HttpOnly cookies where you can.',
      d.storageKeys.slice(0, 10).map((k) => k.where + ': ' + k.key).join('\n')));
  }
  if (d.sourceMaps && d.sourceMaps.length) {
    f.push(F('Information leak', 'low', d.sourceMaps.length + ' source map(s) referenced',
      'Source maps can reveal your original, readable source code, comments and internal paths.',
      'Do not deploy source maps to production, or restrict them to your team.',
      d.sourceMaps.slice(0, 5).join('\n')));
  }

  (d.tech || []).forEach((t) => {
    if (t.name === 'jQuery' && t.version && compareVersions(t.version, '3.5.0') < 0) {
      f.push(F('Third-party code', 'medium', 'Outdated jQuery ' + t.version,
        'jQuery older than 3.5.0 has known cross-site scripting vulnerabilities (CVE-2020-11022 and CVE-2020-11023).',
        'Upgrade to the latest jQuery 3.x release.', 'jQuery ' + t.version));
    }
    if (t.name === 'AngularJS') {
      f.push(F('Third-party code', 'low', 'AngularJS (1.x) is end-of-life',
        'AngularJS stopped receiving security fixes in December 2021.',
        'Plan a migration to a supported framework.', 'AngularJS ' + (t.version || '')));
    }
  });
  return f;
}

export function score(findings) {
  let s = 100;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((x) => { s -= PENALTY[x.severity] || 0; counts[x.severity] = (counts[x.severity] || 0) + 1; });
  s = Math.max(0, s);
  const grade = s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F';
  return { score: s, grade, counts };
}

export function sortFindings(list) {
  return [...list].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
}
