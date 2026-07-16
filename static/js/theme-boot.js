// Theme/FOUC bootstrap — loaded as a synchronous <script> at the top of <head>,
// before the stylesheets, so the resolved theme is stamped on <html> before first
// paint. This replaces the old inline anti-flash script: a strict `script-src
// 'self'` CSP forbids inline scripts, so the bootstrap must be a same-origin file
// (#106). Keep it dependency-free and tiny — it blocks rendering.
//
// Preference model (system/light/dark): the stored preference lives in
// localStorage under `icebergebs-theme` ('system' | 'light' | 'dark'; the legacy
// binary 'light'/'dark' values remain valid). 'system' resolves against
// prefers-color-scheme. Two cookies mirror the state so the server can render
// <html data-theme="…"> on the next request: `ebs_theme` (the preference) and
// `ebs_resolved_theme` (what it resolved to).
(() => {
  const maxAge = 60 * 60 * 24 * 365;
  const readCookie = (name) => {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  };
  const writeCookie = (name, value) => {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=${maxAge}; samesite=lax`;
  };
  const readLocal = (key) => {
    try { return localStorage.getItem(key); } catch { return null; }
  };
  const writeLocal = (key, value) => {
    try { localStorage.setItem(key, value); } catch { /* private mode */ }
  };

  const VALID = ['system', 'light', 'dark'];
  const stored = readLocal('icebergebs-theme');
  const cookie = readCookie('ebs_theme');
  const theme = VALID.includes(stored) ? stored : (VALID.includes(cookie) ? cookie : 'system');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const resolved = theme === 'system' ? (prefersDark ? 'dark' : 'light') : theme;
  // Page background (--paper) inlined so the pre-stylesheet frame is already the
  // right colour — keep in sync with the house tokens in static/css/iceberg.css.
  const bg = resolved === 'dark' ? 'oklch(0.185 0.02 256)' : 'oklch(0.984 0.006 240)';

  document.documentElement.setAttribute('data-theme', resolved);
  document.documentElement.style.backgroundColor = bg;
  document.documentElement.style.colorScheme = resolved;

  writeCookie('ebs_theme', theme);
  writeCookie('ebs_resolved_theme', resolved);
  if (stored !== theme) writeLocal('icebergebs-theme', theme);
})();
