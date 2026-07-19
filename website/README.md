# IcebergEBS documentation site

The public site at **https://icebergai.github.io/IcebergEBS/**, built with
[Zensical](https://zensical.org) (a Material-for-MkDocs–based static site generator)
and styled to the shared **Iceberg** design system — the same setup as the sibling
[IcebergTTX](https://icebergai.github.io/IcebergTTX/) site.

## Layout

```
website/
├─ zensical.toml            # site config (nav, palette, theme, self-hosted fonts)
└─ docs/
   ├─ index.md              # landing page (hero + feature grid + screenshots)
   ├─ scoring.md            # the six risk signals and the 0–100 score
   ├─ deployment.md         # Docker Compose + Helm
   ├─ alerts.md             # webhook alerting + the REST API
   ├─ security.md           # security posture + vulnerability reporting
   ├─ changelog.md          # snippet-includes the repo-root CHANGELOG.md
   ├─ assets/               # brand SVGs, favicon, screenshots
   ├─ fonts/                # self-hosted woff2 (Archivo / JetBrains Mono / Spectral)
   └─ stylesheets/
      ├─ fonts.css          # @font-face rules (path-rewritten from the app's fonts.css)
      └─ iceberg.css        # Iceberg tokens mapped onto Material's --md-* variables
```

## Local preview

```bash
pip install zensical           # into your virtualenv (not in uv.lock — see below)
cd website
zensical serve                 # http://localhost:8000
zensical build --clean         # outputs to website/site/ (git-ignored)
```

Zensical is **deliberately not** a `dev`-group dependency in `pyproject.toml`: it is
only ever installed by the docs workflow (pinned) or ad-hoc for a local preview, so
it stays out of `uv.lock` and off the CI/runtime dependency surface.

## Deployment

Pushes to `main` that touch `website/**` (or `CHANGELOG.md`) trigger
`.github/workflows/docs.yml`, which builds and deploys to GitHub Pages. This requires
**Settings → Pages → Source = "GitHub Actions"** (one-time, in the repository
settings). The workflow pins `zensical==<version>` rather than floating, because the
job holds `pages: write` + `id-token: write`.

## Content rules

- Pages are **hand-written condensations**, not includes — the exception is
  `changelog.md`, which snippet-includes the repo-root `CHANGELOG.md` via
  `--8<--` (`check_paths = true`, so a moved file fails the build instead of
  silently rendering an empty page).
- The site documents the **product**; contributor-facing detail stays in
  `CLAUDE.md` / `CONTRIBUTING.md` and the long-form operator runbook stays in
  `DEPLOYMENT.md`. `docs/deployment.md` links out to it rather than duplicating it.
- Risk-band **thresholds** are stated in `scoring.md` but owned by
  `app/scoring.py:risk_level` — if you change them there, change them here.

## Styling notes

- Fonts are **self-hosted** (no Google Fonts); `font = false` in `zensical.toml`
  disables the default CDN fonts and `stylesheets/fonts.css` provides the woff2.
  That sheet is derived from `../static/css/fonts.css` with the `/static/fonts/`
  URLs rewritten to `../fonts/` — keep the two in sync.
- The palette uses `primary = "custom"` / `accent = "custom"`; the real colours come
  from the Iceberg oklch tokens in `stylesheets/iceberg.css`, which map onto
  Material's `--md-*` variables for both the light (`default`) and dark (`slate`)
  schemes. Keep it in sync with `../static/css/iceberg.css`, and the `--risk-*`
  band colours at the bottom in sync with `../static/css/app.css`.
- Brand assets are the IcebergAI marks; plain-named SVGs carry light ink (for dark
  backgrounds), `-light` variants carry dark ink (for light backgrounds).
- Screenshots in `docs/assets/` are copies of `../docs/screenshots/` — refresh both
  together with the capture scripts in `../scripts/`.
