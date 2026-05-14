# Marvin - Paranoid about Chrome extensions

## Summary
Collect information about extensions for chromium type apps, Chrome, Edge, VSCode etc. and provide risk scoring. Signals considered: permissions, popularity/install count, publisher identity, staleness, code behaviour (eval/obfuscation), and external domains contacted.

## Environment, Frameworks and Libraries
App will always run on Python 3.14 or later.

### Python
- FastAPI
- SQLModel (with aiosqlite for async SQLite)
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
- JetBrains Mono (Google Fonts)
- Gruvbox dark colour palette (CSS custom properties in `static/css/app.css`)


## Architecture
API-first design. All data flows through FastAPI endpoints; the UI consumes them. HTML routes render Jinja2 templates; API routes return JSON.

### Key modules
- `app/config.py` — pydantic-settings `BaseSettings`, env prefix `MARVIN_`
- `app/database.py` — async SQLAlchemy engine, WAL mode enabled at startup
- `app/models.py` — SQLModel table definitions (`User`, `Extension`, `FetchLog`, `InstallCountHistory`, `AlertDestination`, `AlertRule`, `AlertLog`)
- `app/auth.py` — itsdangerous signed cookies, `require_auth` / `require_admin` FastAPI dependencies
- `app/fetchers/` — one fetcher class per store; `get_fetcher(store, client)` factory in `__init__.py`
- `app/inspector.py` — static analysis of downloaded zip packages (CRX/VSIX)
- `app/scoring.py` — pure scoring functions, `compute_risk_score()` → `RiskDetail` NamedTuple
- `app/services.py` — `fetch_and_store()`: shared pipeline used by both API routes and the scheduler
- `app/notifications.py` — `detect_changes()` + `fire_alerts()`: compares old/new extension state and POSTs to matching webhook destinations
- `app/scheduler.py` — APScheduler `AsyncIOScheduler` background watchlist refresh
- `app/routes/api.py` — JSON API routes for extensions (`/api/extensions/...`)
- `app/routes/alerts.py` — JSON API routes for alert destinations, rules, and log (`/api/alerts/...`)
- `app/routes/users.py` — JSON API routes for user management (`/api/users/...`)
- `app/routes/ui.py` — HTML routes, Jinja2 templates, flash messages

### Data flow
1. Caller (API route or scheduler) calls `fetch_and_store(ext, session, client)`
2. `fetch_and_store` calls `fetcher.fetch(extension_id)` → `(ExtensionMetadata, bytes | None)`
3. If package bytes are present, `inspect_package()` runs static analysis
4. `compute_risk_score()` calculates the risk breakdown
5. Extension record, FetchLog, and InstallCountHistory are staged; caller commits

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
- Also extracts `version` and `author` from the manifest for use as fallbacks when the store page cannot provide them (primarily Edge, now less relevant since the API provides these directly)
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
- Use `hmac.compare_digest` for all password comparisons (timing-safe).
- Jinja2 autoescaping is on by default — do not disable it.
- Session cookies: HttpOnly + SameSite=Lax, signed with itsdangerous `URLSafeTimedSerializer`

## Datetime handling
- Always use `datetime.now(timezone.utc)` — never `datetime.utcnow()` (deprecated in Python 3.12+, produces naive datetimes)
- Model `default_factory` uses the shared `_utcnow` lambda in `models.py`
- Scoring functions handle naive datetimes from external sources by attaching UTC tzinfo before comparison

## Styling, Theming and Design
Clean dark UI. CSS custom properties in `static/css/app.css` — ink-* scale for neutral tones (ink-1 darkest background → ink-8 near-white text), risk-* for severity colours. Tailwind CSS utility classes via CDN for layout; component classes (`surface`, `btn`, `badge`, `label-cap`, `page-title`, `section-title`) defined in `app.css`.

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

## Maintenance
- Keep this file up to date with decisions around structure, architecture, and function.
- Ensure the application's help page (`app/templates/help.html`) is up to date and accurate.
