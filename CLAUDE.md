# Marvin - Paranoid about Chrome extensions

## Summary
Collect information about extensions for chromium type apps, Chrome, Edge, VSCode etc. and provide risk scoring. Signals considered: permissions, popularity/install count, publisher identity, staleness, code behaviour (eval/obfuscation), and external domains contacted.

## Environment, Frameworks and Libraries
App will always run on Python 3.14 or later.

### Python
- FastAPI
- SQLModel with `aiosqlite` (tests / SQLite dev) and `asyncpg` (production Postgres)
- HTTPX
- pytest + pytest-asyncio
- pydantic-settings (config from env vars)
- itsdangerous (session cookie signing)
- jinja2 + python-multipart (templates + form parsing)
- uvicorn[standard] (ASGI server)
- beautifulsoup4 (Chrome HTML scraping only)
- apscheduler (3.x stable — 4.x is alpha-only, do not use)

### UI / Front end
- AlpineJS (via CDN)
- Tailwind CSS (via CDN in dev; build output at `static/css/app.css`)
- IBM Plex Sans + IBM Plex Mono (Google Fonts)
- Custom light/dark design system using CSS custom properties (`static/css/app.css`)


## Architecture
API-first design. All data flows through FastAPI endpoints; the UI consumes them. HTML routes render Jinja2 templates; API routes return JSON.

### Key modules
- `app/config.py` — pydantic-settings `BaseSettings`, env prefix `MARVIN_`
- `app/database.py` — async SQLAlchemy engine; SQLite gets WAL mode at startup; Postgres gets a tuned connection pool (`pool_size=5`, `max_overflow=10`, `pool_pre_ping`, `pool_recycle=1800`)
- `app/models.py` — SQLModel table definitions (`User`, `Extension`, `FetchLog`, `InstallCountHistory`, `AlertDestination`, `AlertRule`, `AlertLog`)
- `app/auth.py` — itsdangerous signed cookies, `require_auth` / `require_admin` FastAPI dependencies; `verify_credentials` always runs bcrypt (via `_DUMMY_HASH`) even for unknown usernames to prevent timing-based user enumeration
- `app/fetchers/` — one fetcher class per store; `get_fetcher(store, client)` factory in `__init__.py`
- `app/inspector.py` — static analysis of downloaded zip packages (CRX/VSIX)
- `app/scoring.py` — pure scoring functions, `compute_risk_score()` → `RiskDetail` NamedTuple
- `app/services.py` — `fetch_and_store(ext, session, client, engine=None)`: shared pipeline used by both API routes and the scheduler; stages changes but does **not** commit — the caller commits; pass `engine` to enable alert processing
- `app/notifications.py` — `detect_changes()` + `fire_alerts()`: compares old/new extension state and POSTs to matching webhook destinations; `fire_alerts()` takes an `AsyncEngine` and commits `AlertLog` rows in its own dedicated session, independent of the caller's transaction
- `app/scheduler.py` — APScheduler `AsyncIOScheduler` background watchlist refresh; each extension is processed in its own `AsyncSession` + commit so a single failure cannot corrupt or roll back changes for the entire batch
- `app/routes/api.py` — JSON API routes for extensions (`/api/extensions/...`)
- `app/routes/alerts.py` — JSON API routes for alert destinations, rules, and log (`/api/alerts/...`)
- `app/routes/users.py` — JSON API routes for user management (`/api/users/...`)
- `app/routes/ui.py` — HTML routes, Jinja2 templates, flash messages

### Data flow
1. Caller (API route or scheduler) calls `fetch_and_store(ext, session, client, engine)`
2. `fetch_and_store` calls `fetcher.fetch(extension_id)` → `(ExtensionMetadata, bytes | None)`
3. If package bytes are present, `inspect_package()` runs static analysis
4. `compute_risk_score()` calculates the risk breakdown
5. Extension record, FetchLog, and InstallCountHistory are staged; caller commits
6. `detect_changes()` compares the pre-fetch snapshot against the updated record; if events are found, `fire_alerts()` POSTs webhooks and commits `AlertLog` rows in its own session — decoupled from the caller's transaction so logs survive any subsequent rollback

## Store-specific fetcher notes

### Chrome Web Store (`app/fetchers/chrome.py`)
- Scrapes `https://chromewebstore.google.com/detail/{extension_id}` with BeautifulSoup4
- Publisher extracted via `_find_detail_value(soup, "offered by")` — finds text node then reads next sibling element
- Last updated extracted via `_find_detail_value(soup, "updated")` then `_parse_date()`
- Downloads CRX from `clients2.google.com/service/update2/crx`
- CRX3 format: binary header precedes the zip payload; `_strip_crx_header()` finds the `PK\x03\x04` magic offset

### VS Code Marketplace (`app/fetchers/vscode.py`)
- Uses the public gallery REST API: `POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery` with flags `914`
- Extension ID format: `publisher.extensionName`
- `fetch()` is overridden to make a single API call for both metadata and the VSIX download URL (the base class would otherwise call the API twice)
- Downloads `.vsix` (plain zip, no header stripping needed)

### Edge Add-ons (`app/fetchers/edge.py`)
- The store frontend is a React SPA — static HTML has almost no useful data
- Uses the undocumented product details API discovered via browser XHR inspection:
  `GET https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}?hl=en-US`
- Response fields used: `name`, `developer` (publisher), `version`, `activeInstallCount`, `lastUpdateDate` (Unix timestamp), `description`
- The response also includes the full `manifest` JSON string (with `permissions`, `host_permissions`) and `averageRating`/`ratingCount` (not currently used)
- `fetch()` is overridden to use a two-stage package strategy:
  1. **Guaranteed baseline**: the `manifest` string from the API response is wrapped in a minimal in-memory zip and passed to the inspector — permissions are always available
  2. **Upgrade attempt**: the CRX download is tried (`edge.microsoft.com/extensionwebstorebase/v1/crx`) for full JS static analysis; if it succeeds, the full package replaces the baseline
- CRX download URL format: `?x=id%3D{id}%26installsource%3Dondemand&response=redirect` — the `installsource=ondemand` parameter (URL-encoded within the `x` value) is required; other formats (`%26uc`, `installsource=webstore`) return HTTP 500

### Package inspection (`app/inspector.py`)
- Handles both CRX (header already stripped by fetcher) and VSIX (plain zip)
- Extracts: permissions, host_permissions, eval usage, remote fetch calls, obfuscation score, external domains, minification
- Extracts `author` and `version` from the manifest; only `author` is used as a publisher fallback in `services.py` when the store page returns nothing; `version` from the manifest is intentionally not used — updating `ext.version` only from store metadata avoids spurious `new_version` alerts when Chrome HTML scraping is unreliable
- `_SAFE_DOMAINS` filters out well-known CDNs from the external domain list

## Testing

Ensure tests are added for major functionality changes and regression tests are added where bugs are identified.

### Running Tests
```bash
venv/bin/python -m pytest tests/ -v
```

`pytest.ini` sets `asyncio_mode = auto` so async tests run without extra decoration.

### Test structure
- `tests/conftest.py` — in-memory SQLite fixture, authenticated/anonymous HTTPX test clients, `make_fake_crx()` / `make_fake_vsix()` helpers
- HTTP calls are mocked with `respx`; fetcher classes are mocked with `unittest.mock.patch` in API tests
- Patch target for fetcher mocks is `app.fetchers.VSCodeFetcher` (not `app.routes.api.*`) since `get_fetcher` lives in `app/fetchers/__init__.py`
- Starlette 1.0+ `TemplateResponse` API: use keyword arguments — `TemplateResponse(request=request, name=name, context=ctx)`

## Security
- Security of the application is a priority.
- Validate code to ensure there are no serious security flaws.
- Ensure authentication is applied to endpoints that shouldn't be public.
- `verify_credentials` in `auth.py` always pays the bcrypt cost via `_DUMMY_HASH` when the username doesn't exist — never short-circuit before bcrypt runs or you leak username existence via timing.
- Webhook URLs in `alerts.py` are validated against a hostname blocklist (including subdomain suffixes) and IP range checks (`is_global`, `is_loopback`, `is_link_local`, `is_reserved`) to prevent SSRF.
- Jinja2 autoescaping is on by default — do not disable it.
- Session cookies: HttpOnly + SameSite=Lax, signed with itsdangerous `URLSafeTimedSerializer`

## Datetime handling
- Always use `datetime.now(timezone.utc)` — never `datetime.utcnow()` (deprecated in Python 3.12+, produces naive datetimes)
- Model `default_factory` uses the shared `_utcnow` lambda in `models.py`
- Scoring functions handle naive datetimes from external sources by attaching UTC tzinfo before comparison

## Styling, Theming and Design
Light/dark UI with a toggle in the user dropdown. Theme preference is stored in `localStorage` under `marvin-theme` (`'light'` or `'dark'`) and applied to `<html data-theme="...">` via an inline script in `<head>` before first paint (anti-flash).

CSS custom properties in `static/css/app.css`:
- `--ink-0` (page background, lightest) → `--ink-8` (near-black text, darkest) in light mode; the scale inverts in `[data-theme="dark"]`
- `--surface` replaces hardcoded `white` on all card/panel backgrounds
- `--risk-*` semantic colours for severity levels (low/medium/high/critical)
- `--badge-*-color` and `--perm-*-color` for text inside badges (need separate dark-mode values)

Tailwind CSS utility classes via CDN for layout; component classes (`surface`, `btn`, `badge`, `label-cap`, `page-title`, `section-title`) defined in `app.css`.

The `tailwind.config` object (font families) is in `static/js/tailwind-config.js` loaded via `<script src>` — do not inline it in `base.html` as that would require `unsafe-inline` in the CSP. The anti-flash inline script in `<head>` is the only remaining inline script; its SHA-256 is `KhejTvJfrnJvlOpLJujMQ/zWMQZiBfWaLFOz/LgKBek=` and is included in `nginx/security_headers.conf`. If you change that script, recompute the hash.

### Alpine.js x-data pattern
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

## Deployment

Full production deployment instructions are in `DEPLOYMENT.md`. Two options are covered:

**Docker Compose** — three-service stack (postgres, app, nginx). nginx terminates TLS, enforces rate limits, and serves static assets directly. Single uvicorn worker required (APScheduler is per-process; multiple workers produce duplicate watchlist refreshes and `AlertLog` rows).

**Kubernetes (Helm)** — chart under `helm/marvin/` with Bitnami postgresql subchart. `replicaCount: 1` is mandatory for the same reason. Ingress via nginx-ingress-controller with cert-manager for automatic TLS.

Quick start (Docker):
```bash
bash nginx/generate-dev-cert.sh
cp .env.example .env && $EDITOR .env
docker compose up --build
```

## Maintenance
- Keep this file up to date with decisions around structure, architecture, and function.
- Ensure the application's help page (`app/templates/help.html`) is up to date and accurate.
