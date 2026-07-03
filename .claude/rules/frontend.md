---
description: UI styling/theming, branding (Aperture mark), CSP script hash, and the Alpine.js x-data pattern
paths:
  - "static/**"
  - "app/templates/**"
---

# Styling, Theming and Design
Light/dark UI with a toggle in the user dropdown. Theme preference is stored in `localStorage` under `marvin-theme` (`'light'` or `'dark'`) and applied to `<html data-theme="...">` via an inline script in `<head>` before first paint (anti-flash).

CSS custom properties in `static/css/app.css`:
- `--ink-0` (page background, lightest) → `--ink-8` (near-black text, darkest) in light mode; the scale inverts in `[data-theme="dark"]`
- `--surface` replaces hardcoded `white` on all card/panel backgrounds
- `--risk-*` semantic colours for severity levels (low/medium/high/critical)
- `--badge-*-color` and `--perm-*-color` for text inside badges (need separate dark-mode values)

Tailwind CSS utility classes via CDN for layout; component classes (`surface`, `btn`, `badge`, `label-cap`, `page-title`, `section-title`) defined in `app.css`.

The `tailwind.config` object (font families) is in `static/js/tailwind-config.js` loaded via `<script src>` — do not inline it in `base.html` as that would require `unsafe-inline` in the CSP. The anti-flash inline script in `<head>` is the only inline script; it is byte-identical in `base.html` and `login.html`, so one CSP hash covers both. Its SHA-256 is `WkYC1Fvwnyf6D8gj+0BrUmYBPS4kqMNic5PfT5ccqEw=` and is included in `nginx/security_headers.conf`. If you change that script (in either template), keep both copies identical and recompute the hash.

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
