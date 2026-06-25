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
- `app/version.py` — `get_version()` (lru_cached): resolves the running build as `build N · sha` (`N` = `git rev-list --count --first-parent HEAD`, +1 per merge to main) in priority order `MARVIN_VERSION` env → stamped `app/_version` file → runtime git → `"dev"`. Shown at the bottom of the rail and set as the FastAPI app `version`. See the Versioning section below
- `app/database.py` — async SQLAlchemy engine; SQLite gets WAL mode at startup; Postgres gets a tuned connection pool (`pool_size=5`, `max_overflow=10`, `pool_pre_ping`, `pool_recycle=1800`). Incremental migrations run on startup via `init_db()`: `_migrate_sqlite(conn)` (atomic `alertlog` rebuild, shares the create_all transaction) and `_migrate_postgres()` (each DDL statement in its **own** `engine.begin()` transaction). The per-statement isolation on Postgres is mandatory — sharing one transaction means a single failing statement aborts it and silently skips every later statement (e.g. the `ADD COLUMN user_id/destination_id` on `alertlog`), which then breaks every `AlertLog` insert while webhooks still fire. Do not collapse `_migrate_postgres` back into a shared transaction.
- `app/models.py` — SQLModel table definitions (`User`, `Extension`, `FetchLog`, `InstallCountHistory`, `AlertDestination`, `AlertRule`, `AlertLog`)
- `app/auth.py` — itsdangerous signed cookies, `require_auth` / `require_admin` FastAPI dependencies; `verify_credentials` always runs bcrypt (via `_DUMMY_HASH`) even for unknown usernames to prevent timing-based user enumeration. `hash_password` / `verify_password` are **async** — bcrypt is ~100ms of pure CPU, so they offload to a worker thread via `anyio.to_thread.run_sync` (single uvicorn worker: running it inline stalls every request + the scheduler). All callers must `await` them; the sync cores are `_hash_password_sync` / `_verify_password_sync`. `require_api_auth` **throttles** the `ApiKey.last_used_at` write (only when missing or older than `settings.api_key_last_used_throttle_seconds`, default 60s) — the per-request commit takes the SQLite write lock and contended with the scheduler on every read-only GET. **Session revocation (M1):** every cookie carries a signed issued-at (read via `get_session_claims`); `require_auth`/`require_api_auth` reject cookies older than the user's `User.password_changed_at` (`_session_after_password_change`, 1s tolerance for timestamp granularity), and `change_password` bumps that marker **and** deletes the user's API keys — so a password reset invalidates other-device sessions and leaked bearer tokens. **`require_admin_ui`** is the HTML-admin counterpart to `require_admin`: built on `require_auth` it gives 303 redirects (to `/login` if unauthenticated, `/` if non-admin) instead of raw JSON 401/403
- `app/fetchers/` — one fetcher class per store; `get_fetcher(store, client)` factory in `__init__.py`. Package download is best-effort: `fetch()` (base + vscode/edge overrides) catches **only** `(FetchError, httpx.HTTPError)` → logs + `package=None`; genuine programming errors propagate instead of being swallowed into a silent midpoint-fallback score (M5)
- `app/inspector.py` — static analysis of downloaded zip packages (CRX/VSIX). `inspect_package()` is pure-CPU (~20 regexes over up to 500 JS files); `services.py` calls it via `anyio.to_thread.run_sync` so it doesn't stall the event loop / scheduler
- `app/scoring.py` — pure scoring functions, `compute_risk_score()` → `RiskDetail` NamedTuple; `risk_level(score)` is the single source of truth for the score→band thresholds (75/50/25), reused by `routes/api.py` and `notifications.py` — do not re-inline those thresholds elsewhere
- `app/services.py` — `fetch_and_store(ext, session, client)`: shared pipeline used by both API routes and the scheduler; stages changes but does **not** commit and does **not** fire alerts — it returns `(ext, events)`. `fire_pending_alerts(events, ext, engine, client)`: the caller invokes this **only after committing**. Firing is deferred on purpose: `fire_alerts` opens its own second DB session, and on SQLite a second writer deadlocks against the caller's still-open write transaction → `sqlite3.OperationalError: database is locked` (the webhook still goes out, but the `AlertLog` insert fails). Never call `fire_alerts`/`fire_pending_alerts` while the caller's write transaction is open. After commit, callers `session.refresh(ext)` (reloading expired attrs) before firing, since `fire_alerts` reads `ext` to build the payload.
- `app/notifications.py` — `detect_changes()` + `fire_alerts()`: compares old/new extension state and POSTs to matching webhook destinations (via `app.webhooks.send_webhook`); `fire_alerts()` takes an `AsyncEngine` and commits `AlertLog` rows in its own dedicated session, independent of the caller's transaction. It must run **after** the caller has committed (see `fire_pending_alerts`) so its session does not contend with the caller's SQLite write lock
- `app/webhooks.py` — `validate_webhook_url()` (SSRF validation: scheme/blocklist/IP-range checks, returns the resolved public IPs) and `send_webhook()` (validates + resolves + connects to the pinned IP, preserving the original `Host` header and TLS SNI). DNS resolution is isolated in `_resolve_host()` so tests can stub it. Both `alerts.py` and `notifications.py` send through this module
- `app/scheduler.py` — APScheduler `AsyncIOScheduler` background watchlist refresh; each extension is processed in its own `AsyncSession` + commit so a single failure cannot corrupt or roll back changes for the entire batch
- `app/ratelimit.py` — `LoginRateLimiter` (process-local `login_limiter` singleton) for app-level login throttling (M3), independent of nginx: counts failures per (client IP + username), locks the pair out for `settings.login_lockout_seconds` after `settings.login_max_attempts` within `login_attempt_window_seconds`. In-process state is fine because the deployment mandates a single worker. `login_post` returns 429 + `Retry-After` while locked and `reset()`s on success
- `app/routes/api.py` — JSON API routes for extensions (`/api/extensions/...`). `ExtensionOut.from_db(ext, include_threat_intel=...)`: the list endpoint passes `include_threat_intel=False` to skip the O(extensions × domains/URLs) VirusTotal/OTX indicator build it never renders; single-extension views keep the default `True` (D2)
- `app/routes/alerts.py` — JSON API routes for alert destinations, rules, and log (`/api/alerts/...`)
- `app/routes/users.py` — JSON API routes for user management (`/api/users/...`)
- `app/routes/ui.py` — HTML routes, Jinja2 templates, flash messages

### Data flow
1. Caller (API route or scheduler) calls `fetch_and_store(ext, session, client)`
2. `fetch_and_store` calls `fetcher.fetch(extension_id)` → `(ExtensionMetadata, bytes | None)`
3. If package bytes are present, `inspect_package()` runs static analysis
4. `compute_risk_score()` calculates the risk breakdown
5. Extension record, FetchLog, and InstallCountHistory are staged; `detect_changes()` compares the pre-fetch snapshot against the updated record; `fetch_and_store` returns `(ext, events)`
6. The caller **commits** (releasing the SQLite write lock), `session.refresh(ext)`, then calls `fire_pending_alerts(events, ext, engine, client)` → `fire_alerts()` POSTs webhooks and commits `AlertLog` rows in its own session, decoupled from the caller's transaction. This ordering is mandatory: firing during the caller's open write transaction deadlocks SQLite ("database is locked")

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
- Webhook SSRF protection lives in `app/webhooks.py`. URLs are validated against a hostname blocklist (including subdomain suffixes) and IP range checks (`is_global`, `is_loopback`, `is_link_local`, `is_reserved`). Validation runs both at destination create/update time **and again at send time** in `send_webhook()`, which resolves the host and connects to the validated IP directly (IP pinning) — closing the DNS-rebinding TOCTOU window between validation and the request. Redirects are disabled (`follow_redirects=False`) so a 3xx cannot bounce the POST to a private address.
- Jinja2 autoescaping is on by default — do not disable it.
- Session cookies: HttpOnly + SameSite=Lax, signed with itsdangerous `URLSafeTimedSerializer`. Password change revokes other-device sessions + API keys (see `auth.py` note, M1). Login is throttled app-side by `app/ratelimit.py` (M3).
- Never return raw exception text (`str(exc)`) to API callers on connection/SSRF paths — it can leak resolved IPs / internal hostnames. Log the detail server-side and return a generic message (M4, `alerts.py:test_destination`). `WebhookValidationError` messages are static and intentionally user-facing, so surfacing those at create/update time is fine.

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

The `tailwind.config` object (font families) is in `static/js/tailwind-config.js` loaded via `<script src>` — do not inline it in `base.html` as that would require `unsafe-inline` in the CSP. The anti-flash inline script in `<head>` is the only inline script; it is byte-identical in `base.html` and `login.html`, so one CSP hash covers both. Its SHA-256 is `WkYC1Fvwnyf6D8gj+0BrUmYBPS4kqMNic5PfT5ccqEw=` and is included in `nginx/security_headers.conf`. If you change that script (in either template), keep both copies identical and recompute the hash.

### Branding (Aperture mark)
The brand mark is the **Aperture** logo — two broken concentric rings + a center pupil — authored in a 240×240 viewBox. Brand assets live under `static/img/`: `aperture.svg` (primary, `currentColor`), `favicon.svg` (thicker small-size variant), and the rasterized `favicon-32.png` / `apple-touch-icon.png` (white mark on a `#2D5ED4` rounded tile). In templates the mark is **inlined** so it follows the theme — the rail (`base.html`) and login lockup wrap it in `.brand-tile` (`--accent`), and the login brand panel uses `.brand-tile--ondark`. Favicon `<link>`s are in both `base.html` and `login.html` heads. `login.html` is the "Branded split (Option B)" layout (`.login-split` / `.login-brand*` / `.login-form-col` in `app.css`), collapsing to a single column below 720px.

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

## Versioning
The running build is shown at the bottom of the left rail as `build N · sha` (e.g. `build 142 · 8ebe5f8`), where `N` = `git rev-list --count --first-parent HEAD` (one per merge to main) and `sha` is the short commit. Resolved by `app/version.py:get_version()` (cached once per process) in priority order: `MARVIN_VERSION` env → stamped `app/_version` file (git-ignored) → runtime git → `"dev"`. Injected into every page via `_render()` in `app/routes/ui.py` and rendered in the `rail_footer` block (`.rail-version` in `app.css`).
- **Auto-increment:** on the bare-uvicorn droplet (a git checkout) the number advances on each `git pull` of main — no manual bump.
- **No `.git` (Docker/Helm):** `.dockerignore` strips `.git`, so the image relies on the `MARVIN_VERSION` env (Dockerfile `ARG`/`ENV`). The `.github/workflows/build.yml` workflow computes the same `build N · sha` string and passes it as `--build-arg MARVIN_VERSION`. It checks out with `fetch-depth: 0` — required, or `rev-list --count` is wrong on Actions' shallow clone.
- Keep the format string in sync between `app/version.py:_format()` and the workflow's "Compute version" step.

## Maintenance
- Keep this file up to date with decisions around structure, architecture, and function.
- Ensure the application's help page (`app/templates/help.html`) is up to date and accurate.
