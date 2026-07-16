// Shared frontend runtime (#106). Loaded `defer` on every page BEFORE the Alpine
// CSP build, so the `alpine:init` listener below is registered when Alpine boots.
//
// The app ships @alpinejs/csp under a strict `script-src 'self'` — no inline
// scripts, no eval. That build cannot parse an inline x-data object that defines
// methods/getters, so every component with behaviour is registered here (or in
// static/js/pages/*.js for page-specific components) via Alpine.data(). Server
// data reaches components through <script type="application/json"> islands read
// with readJSON() — never through the x-data attribute, because the CSP
// expression parser does not decode the \uXXXX escapes Jinja's |tojson emits for
// `< > & '`.

/* exported readJSON */
// Read server state from a JSON island by element id (shared by pages/*.js).
function readJSON(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  try {
    return JSON.parse(el.textContent);
  } catch {
    return null;
  }
}

// ── Theme (system/light/dark) ────────────────────────────────────────────
// theme-boot.js owns the pre-paint stamp; this is the runtime switcher the
// user-menu picker drives. Keep the two files' cookie/localStorage contract and
// the --ink-0 backgrounds in sync.

function ebsWriteCookie(name, value) {
  const maxAge = 60 * 60 * 24 * 365;
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=${maxAge}; samesite=lax`;
}

function ebsResolveTheme(theme) {
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  return theme === 'system' ? (prefersDark ? 'dark' : 'light') : theme;
}

/* exported ebsApplyTheme */
function ebsApplyTheme(theme) {
  const resolved = ebsResolveTheme(theme);
  const bg = resolved === 'dark' ? 'oklch(0.185 0.02 256)' : 'oklch(0.984 0.006 240)';
  document.documentElement.setAttribute('data-theme', resolved);
  document.documentElement.style.backgroundColor = bg;
  document.documentElement.style.colorScheme = resolved;
  try {
    localStorage.setItem('icebergebs-theme', theme);
  } catch { /* private mode */ }
  ebsWriteCookie('ebs_theme', theme);
  ebsWriteCookie('ebs_resolved_theme', resolved);
}

function ebsCurrentTheme() {
  try {
    const stored = localStorage.getItem('icebergebs-theme');
    if (['system', 'light', 'dark'].includes(stored)) return stored;
  } catch { /* private mode */ }
  return 'system';
}

// ── Shell components ─────────────────────────────────────────────────────

document.addEventListener('alpine:init', () => {
  // Topbar user menu + theme picker (base.html). Formerly an inline x-data
  // object literal with an inline @click writing localStorage — both are
  // incompatible with the CSP build.
  Alpine.data('userMenu', () => ({
    open: false,
    theme: ebsCurrentTheme(),
    setTheme(theme) {
      this.theme = theme;
      ebsApplyTheme(theme);
    },
  }));
});
