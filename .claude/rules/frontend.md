---
description: UI styling/theming, branding (Aperture mark), CSP script hash, and the Alpine.js x-data pattern
paths:
  - "static/**"
  - "app/templates/**"
---

# Styling, Theming and Design
Light/dark UI with a toggle in the user dropdown. Theme preference is stored in `localStorage` under `icebergebs-theme` (`'light'` or `'dark'`) and applied to `<html data-theme="...">` via an inline script in `<head>` before first paint (anti-flash).

CSS custom properties in `static/css/app.css`:
- `--ink-0` (page background, lightest) → `--ink-8` (near-black text, darkest) in light mode; the scale inverts in `[data-theme="dark"]`
- `--surface` replaces hardcoded `white` on all card/panel backgrounds
- `--risk-*` semantic colours for severity levels (low/medium/high/critical)
- `--badge-*-color` and `--perm-*-color` for text inside badges (need separate dark-mode values)

Tailwind utility classes for layout; component classes (`surface`, `btn`, `badge`, `label-cap`, `page-title`, `section-title`) defined in `app.css`, which is linked **after** `output.css` so it layers over the utility sheet.

## Self-hosted assets (#85 — no CDN at runtime)
Everything the page loads is same-origin; `tests/test_no_third_party_origins.py` fails CI if a template loads an external asset or the CSP allowlists an origin.
- **Tailwind v4** is built by the standalone CLI (via `pytailwindcss`, `dev` dependency group) from `static/css/input.css` into `static/css/output.css` — a **gitignored build artifact**. Rebuild with `make css` after editing `input.css`, `app.css` classes used in markup, or any template/JS that adds utility classes (`make dev` depends on it because docker-compose.dev.yml bind-mounts the source over `/app`). Images build it in the Dockerfile `tailwind-builder` stage, which downloads the CLI binary from the tagged GitHub release and **sha256-verifies it before running** (no pip in the image build — a floating wrapper install was a review-bot blocker on #210); the ci.yml lint job builds it as an early syntax gate. The CLI version is pinned by `TAILWINDCSS_VERSION=v4.3.1` in the Makefile and ci.yml and by the per-arch checksum table in the Dockerfile — bump all together, refreshing the checksums from the release's `sha256sums.txt`. Font families (formerly the `static/js/tailwind-config.js` Play-CDN shim) live in the `@theme` block of `input.css`, and `@source` there pins the class-scan surface — never point it at `static/js/vendor/`.
- **Alpine.js** is vendored, version-pinned in the filename: `static/js/vendor/alpine-3.15.12.min.js` (standard build, from npm `alpinejs@3.15.12/dist/cdn.min.js`, sha256 `57b37d7cae9a27d965fdae4adcc844245dfdc407e655aee85dcfff3a08036a3f`). To bump: download the new dist file from the npm registry, rename with the version, update both this note and the `<script>` tag in `base.html`.
- **Fonts** are self-hosted woff2 under `static/fonts/` (IBM Plex Sans 400/500/600/700 + Mono 400/500, latin/latin-ext, from `@fontsource/ibm-plex-{sans,mono}` 5.2.7) declared in `static/css/fonts.css`.

The anti-flash inline script in `<head>` is the only inline script; it is byte-identical in `base.html` and `login.html`, so one CSP hash covers both. Its SHA-256 is `+Eb7yRWu45ifRb64zPIDP0hvsT4OloSS8kNklIXpCO4=` and is included in `caddy/headers.caddy` (the single CSP home, imported by both the Compose and K8s Caddyfiles; the Helm ConfigMap embeds a test-guarded mirror). If you change that script (in either template), keep both copies identical and recompute the hash, then update `caddy/headers.caddy` and re-mirror the Helm ConfigMap (`tests/test_csp_hash.py` / `tests/test_helm_caddy.py` enforce this).

**Why the hash pins are test-guarded:** in the pre-Caddy layout the hash lived in two hand-maintained copies (nginx conf + Helm ingress) which silently diverged — the Helm CSP blocked the very script it was meant to allow, and nothing at runtime noticed except dark mode silently not applying. `tests/test_csp_hash.py` computes the hash from the template and asserts every pin matches, so a drift now fails CI rather than shipping. The hashed bytes include the script's **trailing semicolon**.

## Branding (Aperture mark)
The brand mark is the **Aperture** logo — two broken concentric rings + a center pupil — authored in a 240×240 viewBox. Brand assets live under `static/img/`: `aperture.svg` (primary, `currentColor`), `favicon.svg` (thicker small-size variant), and the rasterized `favicon-32.png` / `apple-touch-icon.png` (white mark on a `#2D5ED4` rounded tile). In templates the mark is **inlined** so it follows the theme — the rail (`base.html`) and login lockup wrap it in `.brand-tile` (`--accent`), and the login brand panel uses `.brand-tile--ondark`. Favicon `<link>`s are in both `base.html` and `login.html` heads. `login.html` is the "Branded split (Option B)" layout (`.login-split` / `.login-brand*` / `.login-form-col` in `app.css`), collapsing to a single column below 720px.

## Alpine.js x-data pattern
**Never embed `{{ data | tojson }}` directly inside an `x-data="{ ... }"` HTML attribute.** JSON contains `"` which terminates the HTML attribute, breaking the component silently. Always use the function pattern instead:

```html
<div x-data="myComponent()">
...
<script>
function myComponent() {
  return {
    items: {{ items | tojson }},  {# safe — inside <script>, not an HTML attribute #}
    ...
  };
}
</script>
```

This is already the pattern used by `account.html` (accountPrefs) and `dashboard.html` (dashboardData).
