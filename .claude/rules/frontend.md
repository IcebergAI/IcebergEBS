---
description: UI styling/theming, branding (Aperture mark), the strict CSP (no inline scripts), and the Alpine CSP-build component registry
paths:
  - "static/**"
  - "app/templates/**"
---

# Styling, Theming and Design
Light/dark UI with a **system/light/dark** picker in the user dropdown (#106). The preference lives in `localStorage` under `icebergebs-theme` (`'system' | 'light' | 'dark'`); `'system'` resolves against `prefers-color-scheme`. The resolved value is applied to `<html data-theme="...">` before first paint by **`static/js/theme-boot.js`** — an *external, synchronous* script at the top of `<head>` (a strict `script-src 'self'` forbids inline scripts). It also mirrors the state into the `ebs_theme` / `ebs_resolved_theme` cookies so `routes/ui.py:_render()` pre-stamps `data-theme` server-side; the runtime switcher is `ebsApplyTheme()` in `static/js/app.js` (the `userMenu` component). Keep theme-boot.js and app.js in sync on the cookie/localStorage contract and the two `--ink-0` background literals.

CSS custom properties in `static/css/app.css`:
- `--ink-0` (page background, lightest) → `--ink-8` (near-black text, darkest) in light mode; the scale inverts in `[data-theme="dark"]`
- `--surface` replaces hardcoded `white` on all card/panel backgrounds
- `--risk-*` semantic colours for severity levels (low/medium/high/critical)
- `--badge-*-color` and `--perm-*-color` for text inside badges (need separate dark-mode values)

Tailwind utility classes for layout; component classes (`surface`, `btn`, `badge`, `label-cap`, `page-title`, `section-title`) defined in `app.css`, which is linked **after** `output.css` so it layers over the utility sheet.

## Self-hosted assets (#85 — no CDN at runtime)
Everything the page loads is same-origin; `tests/test_no_third_party_origins.py` fails CI if a template loads an external asset or the CSP allowlists an origin.
- **Tailwind v4** is built by the standalone CLI (via `pytailwindcss`, `dev` dependency group) from `static/css/input.css` into `static/css/output.css` — a **gitignored build artifact**. Rebuild with `make css` after editing `input.css`, `app.css` classes used in markup, or any template/JS that adds utility classes (`make dev` depends on it because docker-compose.dev.yml bind-mounts the source over `/app`). Images build it in the Dockerfile `tailwind-builder` stage, which downloads the CLI binary from the tagged GitHub release and **sha256-verifies it before running** (no pip in the image build — a floating wrapper install was a review-bot blocker on #210); the ci.yml lint job builds it as an early syntax gate. The CLI version is pinned by `TAILWINDCSS_VERSION=v4.3.1` in the Makefile and ci.yml and by the per-arch checksum table in the Dockerfile — bump all together, refreshing the checksums from the release's `sha256sums.txt`. Font families (formerly the `static/js/tailwind-config.js` Play-CDN shim) live in the `@theme` block of `input.css`, and `@source` there pins the class-scan surface — never point it at `static/js/vendor/`.
- **Alpine.js** is vendored, version-pinned in the filename: `static/js/vendor/alpine-csp-3.15.12.min.js` — the **`@alpinejs/csp` build** (#106; from npm `@alpinejs/csp@3.15.12/dist/cdn.min.js`, sha256 `566167134bb2347110904e2ced6e816d2e8d837200c158f98b72372b3bb0b9a6`), never the standard build (it needs `unsafe-eval`, which the CSP doesn't grant). To bump: download the new dist file from the npm registry, rename with the version, update both this note and the `<script>` tag in `base.html`.
- **Fonts** are self-hosted woff2 under `static/fonts/` (IBM Plex Sans 400/500/600/700 + Mono 400/500, latin/latin-ext, from `@fontsource/ibm-plex-{sans,mono}` 5.2.7) declared in `static/css/fonts.css`.

## Strict CSP — no inline scripts, ever (#106)
`script-src` is exactly `'self'` (`caddy/headers.caddy` — the single CSP home; the Helm ConfigMap embeds a test-guarded mirror). There is **no inline `<script>` anywhere** and no hash pin to maintain: the pre-#106 design (one hash-pinned inline anti-flash script) is retired, replaced by the external `theme-boot.js`. `tests/test_csp_strict.py` enforces all of it — no inline `<script>` in any template (JSON islands excepted), no `on*=` handler attributes, `script-src` exactly `'self'`, no lingering `sha256-` pins. The runtime backstop is the e2e suite: any CSP console error fails the `ui` job (`_KNOWN_CSP_GAPS` is empty — never add to it). `style-src` keeps `'unsafe-inline'` deliberately for the pervasive inline `style=` attributes; style injection is not a script-execution vector.

If you touch `caddy/headers.caddy`, re-mirror `helm/iceberg-ebs/templates/caddy-configmap.yaml` byte-for-byte (`tests/test_helm_caddy.py` enforces it).

## Branding (Aperture mark)
The brand mark is the **Aperture** logo — two broken concentric rings + a center pupil — authored in a 240×240 viewBox. Brand assets live under `static/img/`: `aperture.svg` (primary, `currentColor`), `favicon.svg` (thicker small-size variant), and the rasterized `favicon-32.png` / `apple-touch-icon.png` (white mark on a `#2D5ED4` rounded tile). In templates the mark is **inlined** so it follows the theme — the rail (`base.html`) and login lockup wrap it in `.brand-tile` (`--accent`), and the login brand panel uses `.brand-tile--ondark`. Favicon `<link>`s are in both `base.html` and `login.html` heads. `login.html` is the "Branded split (Option B)" layout (`.login-split` / `.login-brand*` / `.login-form-col` in `app.css`), collapsing to a single column below 720px.

## Alpine components — the CSP-build registry pattern (#106)
The `@alpinejs/csp` build cannot evaluate an inline `x-data` object that defines methods or getters, so **every component is a factory registered via `Alpine.data()` inside an `alpine:init` listener in a same-origin file**: shell components in `static/js/app.js` (`userMenu`), page components in `static/js/pages/<page>.js`, loaded through the `{% block page_js %}` head block. **Load order is an invariant**: deferred scripts execute in document order, and base.html loads `app.js` → `topbar-search.js` → `{% block page_js %}` → **the Alpine CSP build last**, so every registry's `alpine:init` listener exists when Alpine boots. Never load a registry script after Alpine, and never put page scripts at the end of `<body>`.

**Server data goes through `<script type="application/json" id="...">{{ data | tojson }}</script>` islands** read with the shared `readJSON(id)` helper (app.js) — never through the `x-data` attribute: JSON's `"` terminates the HTML attribute, and the CSP expression parser doesn't decode the `\uXXXX` escapes `|tojson` emits for `< > & '`. Existing islands: `dashboard-data`, `ext-data`, `account-data`, `keys-data`, `users-data`, `score-history`.

**Directive expressions must stay within the CSP parser's grammar** (what deep_thought/iceberg use in production): property paths, bare method calls and calls with simple args, assignments, `!`/`!!`, comparisons, `&&`/`||`, ternaries, string `+` concat, `.trim()`/`.includes()`-style calls on scope properties. **Not supported** — arrow functions (`=>` tokenises as an unexpected `>` operator), template literals, `??`, `new …`, and any global (`window`, `document`, `localStorage`): put those in a component method/getter instead. No `x-html` (use `$refs` + `innerHTML` inside a method if ever needed).
