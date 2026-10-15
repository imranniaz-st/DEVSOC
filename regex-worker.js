// Runs regex tests off the main thread so a catastrophic pattern can be stopped after 1.5 seconds.
self.onmessage = (e) => {
  const { pattern, flags, text } = e.data;
  try {
    const clean = Array.from(new Set((flags || '').split('').filter((c) => 'dgimsuy'.includes(c)))).join('');
    const re = new RegExp(pattern, clean.includes('g') ? clean : clean + 'g');
    const matches = [];
    let m;
    while ((m = re.exec(text)) !== null && matches.length < 200) {
      matches.push({ index: m.index, match: m[0], groups: m.slice(1) });
      if (m[0] === '') re.lastIndex++;
    }
    self.postMessage({ ok: true, matches, truncated: matches.length >= 200 });
  } catch (err) {
    self.postMessage({ ok: false, error: String(err.message) });
  }
};
