# Marvin - Paranoid about Chrome extensions

## Summary
Collect information about extensions for chromium type apps, Chrome, Edge, VSCode etc. and provide risk scoring. Signals considered: permissions, popularity/install count, publisher identity, staleness, code behaviour (eval/obfuscation), and external domains contacted.

## Environment, Frameworks and Libraries
App will always run on Python 3.14 or later.

### Python
- FastAPI
- SQLModel with `asyncpg` (PostgreSQL — dev, test, and production; SQLite is not supported). `psycopg2-binary` (dev only) backs the Alembic CLI / sync-engine paths.
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
- `app/main.py` — FastAPI app + lifespan. Unauthenticated ops probes (#26): **`/healthz`** (liveness — process up, no dependency checks) and **`/readyz`** (readiness — runs `SELECT 1`, returns 503 if the DB is unreachable). Helm/Compose probes point at these. The dashboard (`routes/ui.py`) surfaces per-extension last fetch status/error and a fleet **"Fetch health"** count of watchlist extensions that are failing (latest `FetchLog.success` is false) or stale (no successful refresh within `max(2× fetch_interval, 60m)`)
- `app/config.py` — pydantic-settings `BaseSettings`, env prefix `MARVIN_`
- `app/version.py` — `get_version()` (lru_cached): resolves the running build as `build N · sha` (`N` = `git rev-list --count --first-parent HEAD`, +1 per merge to main) in priority order `MARVIN_VERSION` env → stamped `app/_version` file → runtime git → `"dev"`. Shown at the bottom of the rail and set as the FastAPI app `version`. See the Versioning section below
- `app/database.py` — async SQLAlchemy engine (PostgreSQL) with a tuned connection pool (`pool_size=5`, `max_overflow=10`, `pool_pre_ping`, `pool_recycle=1800`). **Schema is managed by Alembic** (D1): `init_db()` opens a connection and `run_sync`s `_run_migrations`, which upgrades an empty database to head from the baseline, or — for a database created the old way (tables present, no `alembic_version`) — **stamps** it to head without recreating anything. The version INSERT is committed explicitly (`await conn.commit()`) because the connection isn't in autocommit, so the DML row would otherwise roll back when the connection closes. Migration env in `alembic/` (`env.py` reads `settings.database_url`, registers `SQLModel.metadata`, and reuses the startup connection via `config.attributes["connection"]`); baseline revision in `alembic/versions/`. **Adopting Alembic assumes existing production DBs are already on the final pre-Alembic schema** (they are — the retired `_migrate_*` ran on every prior startup) before being stamped. Add new schema changes with `alembic revision --autogenerate`; `tests/test_migrations.py::test_head_matches_models` fails if the baseline/head drifts from `models.py`.
- `app/models.py` — SQLModel table definitions (`User`, `Extension`, `FetchLog`, `InstallCountHistory`, `InstallObservation`, `AlertDestination`, `AlertRule`, `AlertLog`). Timestamp columns use `sa_column=_tz_column(...)` (`timestamptz`) because the app writes tz-aware UTC datetimes. **Referential cleanup lives in the schema** via FK `ondelete` (the SQLModel-recommended pattern): history-preserving FKs are `SET NULL` (`AlertLog.{rule_id,destination_id,user_id}`, `Extension.user_id`), child rows removed with their parent are `CASCADE` (config rows + per-extension `FetchLog`/`InstallCountHistory`/`InstallObservation`/`AlertRule`/`AlertLog`). The delete handlers rely on these instead of hand-severing FKs — see the FK migration `…_fk_ondelete.py`. **`InstallObservation`** (#29) is SOAR-fed org inventory: one row per `(extension_id, asset_id)` (unique constraint → re-pushes upsert `last_seen`), carrying `asset_type`/`department`/`source`/`first_seen`. `Extension.install_footprint` caches the distinct-asset count, maintained by `POST /api/inventory`; **exposure** ("blast radius") = `risk_score × install_footprint` is always **derived** (never stored)
- `app/auth.py` — itsdangerous signed cookies, `require_auth` / `require_admin` FastAPI dependencies; `verify_credentials` always runs bcrypt (via `_DUMMY_HASH`) even for unknown usernames to prevent timing-based user enumeration. `hash_password` / `verify_password` are **async** — bcrypt is ~100ms of pure CPU, so they offload to a worker thread via `anyio.to_thread.run_sync` (single uvicorn worker: running it inline stalls every request + the scheduler). All callers must `await` them; the sync cores are `_hash_password_sync` / `_verify_password_sync`. `require_api_auth` **throttles** the `ApiKey.last_used_at` write (only when missing or older than `settings.api_key_last_used_throttle_seconds`, default 60s) — a commit per request (including read-only GETs) is a wasted write that contends with the scheduler under load. **Session revocation (M1):** every cookie carries a signed issued-at (read via `get_session_claims`); `require_auth`/`require_api_auth` reject cookies older than the user's `User.password_changed_at` (`_session_after_password_change`, 1s tolerance for timestamp granularity), and `change_password` bumps that marker **and** deletes the user's API keys — so a password reset invalidates other-device sessions and leaked bearer tokens. **`require_admin_ui`** is the HTML-admin counterpart to `require_admin`: built on `require_auth` it gives 303 redirects (to `/login` if unauthenticated, `/` if non-admin) instead of raw JSON 401/403
- `app/fetchers/` — one fetcher class per store; `get_fetcher(store, client)` factory in `__init__.py`. Package download is best-effort: `fetch()` (base + vscode/edge overrides) catches **only** `(FetchError, httpx.HTTPError)` → logs + `package=None`; genuine programming errors propagate instead of being swallowed into a silent midpoint-fallback score (M5)
- `app/inspector.py` — static analysis of downloaded zip packages (CRX/VSIX). `inspect_package()` is pure-CPU (~20 regexes over up to 500 JS files); `services.py` calls it via `anyio.to_thread.run_sync` so it doesn't stall the event loop / scheduler
- `app/permissions.py` — single source of truth for the permission-tier sets (`CRITICAL_PERMISSIONS`, `HIGH_PERMISSIONS`, `MEDIUM_PERMISSIONS`, `BROAD_HOST_PATTERNS`). Imported by both `scoring.py` (score) and `inspector.py` (findings) so the two can't drift (#63) — add a permission to a tier here, never re-inline these sets
- `app/scoring.py` — pure scoring functions, `compute_risk_score()` → `RiskDetail` NamedTuple; `risk_level(score)` is the single source of truth for the score→band thresholds (75/50/25), reused by `routes/api.py` and `notifications.py` — do not re-inline those thresholds elsewhere. Permission tiers come from `app/permissions.py`
- `app/services.py` — `fetch_and_store(ext, session, client)`: shared pipeline used by both API routes and the scheduler; stages changes but does **not** commit and does **not** fire alerts — it returns `(ext, events)`. `fire_pending_alerts(events, ext, engine, client)`: the caller invokes this **only after committing**. Firing is deferred on purpose: `fire_alerts` opens its own second DB session, which must not run inside the caller's still-open write transaction (it would contend with / be isolated from the caller's uncommitted writes). Never call `fire_alerts`/`fire_pending_alerts` while the caller's write transaction is open. After commit, callers `session.refresh(ext)` (reloading expired attrs) before firing, since `fire_alerts` reads `ext` to build the payload.
- `app/notifications.py` — `detect_changes()` + `fire_alerts()`: compares old/new extension state and POSTs to matching webhook destinations (via `app.webhooks.send_webhook`); `fire_alerts()` takes an `AsyncEngine` and commits `AlertLog` rows in its own dedicated session, independent of the caller's transaction. It must run **after** the caller has committed (see `fire_pending_alerts`) so its session does not run inside the caller's open write transaction. The `permission_change` event diffs **both** API permissions (`ext.permissions`) **and** host permissions (read from the stored `package_analysis` via `_host_permissions`) — gaining broad host access like `<all_urls>` must alert (#60); both fields are only rewritten on a fresh successful inspection, so a transient download failure can't fire a spurious change
- `app/webhooks.py` — `validate_webhook_url()` (SSRF validation: scheme/blocklist/IP-range checks, returns the resolved public IPs) and `send_webhook()` (validates + resolves + connects to the pinned IP, preserving the original `Host` header and TLS SNI). DNS resolution is isolated in `_resolve_host()` so tests can stub it. Both `alerts.py` and `notifications.py` send through this module
- `app/scheduler.py` — APScheduler `AsyncIOScheduler` background watchlist refresh; each extension is processed in its own `AsyncSession` + commit so a single failure cannot corrupt or roll back changes for the entire batch. Also registers a **daily retention prune** (`run_retention_prune`) — only when `settings.retention_days > 0`
- `app/retention.py` — data-retention pruning (#22). `prune_expired(session, retention_days, now=...)` deletes `FetchLog`/`InstallCountHistory`/`AlertLog` rows older than the window (cutoff = `now − retention_days`), returns per-table delete counts, and is a no-op when `retention_days <= 0`; `Extension` rows are never touched. `run_retention_prune()` is the scheduler entry point — own session + commit, gated by `MARVIN_RETENTION_DAYS` (default 0 = disabled)
- `app/ratelimit.py` — `LoginRateLimiter` (process-local `login_limiter` singleton) for app-level login throttling (M3), independent of nginx: counts failures per (client IP + username), locks the pair out for `settings.login_lockout_seconds` after `settings.login_max_attempts` within `login_attempt_window_seconds`. In-process state is fine because the deployment mandates a single worker. `login_post` returns 429 + `Retry-After` while locked and `reset()`s on success
- `app/deps.py` — reusable FastAPI dependency aliases (`SessionDep`, `CurrentUser`, `WebUser`, `AdminUser`, `AdminUserUI`) used across route signatures instead of repeating `Annotated[..., Depends(...)]`. Each `/api` router declares its own `prefix="/api"` + `tags=[...]` on the `APIRouter` (so `main.py` just `include_router(...)` with no prefix, and `/docs` is grouped by tag). Endpoints declare their public schema as a **return-type annotation** (`-> ExtensionOut`, `-> list[UserOut]`, …) rather than the `response_model=` decorator arg — the FastAPI-preferred form, since the handlers already return the DTO
- `app/routes/api.py` — JSON API routes for extensions (`/api/extensions/...`). `ExtensionOut.from_db(ext, include_threat_intel=...)`: the list endpoint passes `include_threat_intel=False` to skip the O(extensions × domains/URLs) VirusTotal/OTX indicator build it never renders; single-extension views keep the default `True` (D2). **`GET /api/extensions` is paginated + filterable (#23):** returns a `PaginatedExtensions` envelope `{items, total, limit, offset}` (not a bare list) and accepts `store`/`risk`/`publisher`/`q` (search over name/publisher/id, LIKE-escaped)/`sort`/`order`/`limit` (≤200)/`offset`. The filter+sort logic lives in the shared **`build_extension_query(user_id, filters)`** helper (plus `_count`), reused by the dashboard and the export endpoint; it takes an **`ExtensionFilters`** dataclass so the three call sites can't drift (#68). The list + export endpoints collect those params via the **`extension_filters` FastAPI dependency** (`FilterParams`) declared once (typed Query params → 422 on bad input); the dashboard builds the same dataclass from its own coerced strings (tolerating junk). `_RISK_BANDS` maps risk levels to score ranges using the same 75/50/25 thresholds as `scoring.risk_level`. **`GET /api/extensions/export?format=csv|json` (#25):** streams the full (filtered, unpaginated) set of `EXPORT_FIELDS` (score + key fields, no nested findings/threat-intel) with a `Content-Disposition` attachment; shares the same filter/sort params. **Route order matters** — `/extensions/export` and `/extensions/bulk` are registered before `/extensions/{ext_id}` so `"export"`/`"bulk"` aren't parsed as int ids. **`POST /extensions/bulk` (#24):** enrolls many extensions in one request (cap `MAX_BULK_ITEMS=100`), accepting structured `items` and/or a pasted `text` blob (`store,id` per line or store URLs via `_detect_store`/`_parse_bulk_text`). Each entry runs through the shared **`_enroll_extension`** primitive (validate → dedupe → create + `_fetch_and_score`, discarding the placeholder on a failed first fetch) — the same helper `add_extension` now uses — and returns a per-entry status (added/duplicate/invalid/error) + tallies. The loop captures `current_user.id` **before** processing because each enroll commits (expiring the ORM attribute). **`POST /api/inventory` (#29):** bulk-upserts SOAR install inventory (cap `MAX_INVENTORY_ITEMS=1000`); each observation resolves its extension through the same `_enroll_extension` primitive called with **`score=False`** (#78) — so an **unknown** extension is auto-enrolled onto the watchlist but its **scoring is deferred to the scheduler** (which scores every `watchlist=True` extension on its next run), keeping a large batch of unknown extensions from doing hundreds of sequential store fetches inside one request. Newly-created rows report status `deferred`; already-tracked ones report `observed`. `_upsert_observation` then writes/refreshes an `InstallObservation` keyed on `(extension, asset)` via a Postgres `INSERT … ON CONFLICT DO UPDATE` (#76). After the batch, each touched extension's cached `install_footprint` (distinct asset count) is recomputed in one pass. **Exposure** is sortable everywhere via `sort=exposure` — `_SORT_COLUMNS["exposure"]` is the SQL expression `_EXPOSURE_EXPR = Extension.risk_score * Extension.install_footprint` (NULL when either factor is, so existing nullslast handling applies); `ExtensionOut`/`EXPORT_FIELDS` expose `install_footprint` + `exposure` (computed by the `_exposure()` helper mirroring the SQL)
- `app/routes/alerts.py` — JSON API routes for alert destinations, rules, and log (`/api/alerts/...`)
- `app/routes/users.py` — JSON API routes for user management (`/api/users/...`). `delete_user` **preserves history** like `delete_rule`/`delete_destination` (#28): the user's config rows (rules, destinations, API keys) `CASCADE` away and the `AlertLog` FKs `SET NULL` via the schema's `ondelete` actions, so `AlertLog`/`FetchLog`/`InstallCountHistory` survive the account deletion. The one piece still done explicitly is **orphaning** the user's extensions (`user_id=None`, `watchlist=False`) — the FK `SET NULL` alone would null the owner but leave them on the watchlist
- `app/routes/ui.py` — HTML routes, Jinja2 templates, flash messages. The **dashboard** does server-side filter/search/sort/pagination via the shared `build_extension_query` (page size 25), tolerating junk query params (falls back to defaults instead of 422); stat tiles use a lightweight column-only fleet snapshot, and a `qs(**overrides)` context helper builds filter/sort/page links that preserve state. It also renders a **"Top exposure"** section (#29) — a column-only top-5 query ordered by `_EXPOSURE_EXPR` over extensions with a known footprint — and the **extension detail** page adds an **"Org footprint"** card (installed-on-N-assets + exposure + a per-department breakdown queried via `count(distinct asset_id) GROUP BY department`)

### Data flow
1. Caller (API route or scheduler) calls `fetch_and_store(ext, session, client)`
2. `fetch_and_store` calls `fetcher.fetch(extension_id)` → `(ExtensionMetadata, bytes | None)`
3. If package bytes are present, `inspect_package()` runs static analysis
4. `compute_risk_score()` calculates the risk breakdown
5. Extension record, FetchLog, and InstallCountHistory are staged; `detect_changes()` compares the pre-fetch snapshot against the updated record; `fetch_and_store` returns `(ext, events)`
6. The caller **commits**, `session.refresh(ext)`, then calls `fire_pending_alerts(events, ext, engine, client)` → `fire_alerts()` POSTs webhooks and commits `AlertLog` rows in its own session, decoupled from the caller's transaction. This ordering is mandatory: `fire_alerts`' second session must not run inside the caller's open write transaction

## Store-specific fetcher notes

### Chrome Web Store (`app/fetchers/chrome.py`)
- Scrapes `https://chromewebstore.google.com/detail/{extension_id}` with BeautifulSoup4
- Publisher extracted via `_find_detail_value(soup, "offered by")` — finds text node then reads next sibling element
- Last updated extracted via `_find_detail_value(soup, "updated")` then `_parse_date()`
- Downloads CRX from `clients2.google.com/service/update2/crx`
- CRX3 format: a binary header precedes the zip payload. The fetchers download the raw CRX as-is; the header is stripped downstream by `inspector._zip_payload()`, which seeks the `PK\x03\x04` zip magic before reading the archive (the fetchers do **not** pre-strip it)

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
The suite runs against a **real Postgres** (no SQLite). Start the dev Postgres, then run pytest pointed at it:
```bash
make db   # docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
MARVIN_TEST_DATABASE_URL=postgresql+asyncpg://marvin:marvin@localhost:5432/marvin venv/bin/python -m pytest tests/ -v
# or simply: make test
```
`MARVIN_TEST_DATABASE_URL` selects the test database (falls back to `MARVIN_DATABASE_URL`).

`pytest.ini` sets `asyncio_mode = auto` so async tests run without extra decoration. It also pins `asyncio_default_fixture_loop_scope`/`asyncio_default_test_loop_scope` to `session` because the test DB is a single **session-scoped** Postgres engine (`tests/conftest.py`) shared by all tests — fixtures and tests must run on one event loop or asyncpg raises "attached to a different loop". Per-test isolation is the autouse `_clean_tables` fixture, which `TRUNCATE … RESTART IDENTITY CASCADE`s every table after each test.

### CI gates
`.github/workflows/ci.yml` runs four **blocking** jobs on every PR + push to main: **test** (pytest, with a `postgres:16-alpine` service container + `MARVIN_TEST_DATABASE_URL`), **lint** (`ruff check` + `ruff format --check`), **types** (`mypy app`), **security** (`bandit -c pyproject.toml -r app` + `pip-audit -r requirements.txt`). All tool config is in `pyproject.toml`; dev tooling is in `requirements-dev.txt`. Notes:
- **Ruff** selects `E,F,W,I,B` (ignores `E501`, `B008` — the FastAPI `Depends`/`Query` default idiom). Deliberately **no `UP`** (pyupgrade) to preserve the documented `timezone.utc` / `Optional[...]` conventions.
- **mypy** uses `pydantic.mypy` and enforces types only on the **pure logic / contract modules**; the ORM-query modules (`app.routes.*`, `services`, `scheduler`, `notifications`, `retention`, `database`, `fetchers.*`) are excluded via `ignore_errors` because mypy can't see through SQLModel's declarative column attributes (it reads `Extension.last_updated` as a plain `datetime`). When adding a pure-logic module, keep it type-clean rather than excluding it.
- **Bandit** benign findings are annotated inline with justified `# nosec` (git subprocess in `version.py`, best-effort file-skip loops in `inspector.py`) — keep the gate at full strictness rather than lowering severity.
- The separate `build.yml` (Docker image on push to main) is unchanged.

### Test structure
- `tests/conftest.py` — session-scoped Postgres engine + autouse `_clean_tables` TRUNCATE fixture, authenticated/anonymous HTTPX test clients, `make_fake_crx()` / `make_fake_vsix()` helpers
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
- **CSRF (deliberate, documented — #16):** there are **no CSRF tokens**; protection is `SameSite=Lax` (+ `Secure` in prod) on the session cookie, and the JSON API requires an `application/json` body (which browsers can't send cross-origin via a plain form) with Bearer tokens as the primary M2M credential. This is a conscious trade-off, not an oversight (see the comment in `auth.py:set_session`). If a cookie-authenticated, state-changing browser flow ever needs more defense-in-depth, add per-request CSRF tokens in `set_session` + the templates rather than relying on SameSite alone.
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

**Database:** **PostgreSQL only** — dev, test, and production (SQLite support was removed). Postgres' row-level locking/MVCC lets the concurrent writers (scheduler + interactive API/UI + bulk ingestion) proceed without contention and scales the history tables. All writers are commit-isolated (scheduler, retention prune, and `fire_pending_alerts` after commit). Dev runs against a containerized Postgres (`docker-compose.dev.yml` / `make dev`); the Compose/Helm stacks provision it for production; rationale lives in `DEPLOYMENT.md → Database choice`.

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
