# Marvin — Full App Implementation Plan

## Context

Marvin is a greenfield web app to track browser/editor extensions (Chrome, Edge, VS Code) and score them for risk. The project directory currently contains only `CLAUDE.md`. This plan covers building the entire application from scratch.

**User decisions captured:**
- Stores: Chrome Web Store + VS Code Marketplace + Edge Add-ons (all three)
- Data entry: manual add (immediate fetch) + watchlist with scheduled background refresh
- Auth: single admin user from env vars (no user DB)
- Risk signals: permissions, popularity/install count, publisher, staleness

---

## File Structure

```
marvin/
├── CLAUDE.md
├── PLAN.md
├── README.md
├── .env.example
├── pytest.ini
├── requirements.txt
│
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI app factory + lifespan
│   ├── config.py                # pydantic-settings BaseSettings
│   ├── database.py              # SQLModel engine + async session factory
│   ├── models.py                # SQLModel table definitions
│   ├── auth.py                  # itsdangerous session, login dependency
│   ├── scoring.py               # Risk scoring engine (pure functions)
│   ├── scheduler.py             # APScheduler background refresh
│   │
│   ├── fetchers/
│   │   ├── __init__.py
│   │   ├── base.py              # Abstract base + ExtensionMetadata schema
│   │   ├── chrome.py            # Chrome Web Store scraper + .crx download
│   │   ├── vscode.py            # VS Code Marketplace REST API + .vsix download
│   │   └── edge.py              # Edge Add-ons scraper + .crx download
│   │
│   ├── inspector.py             # Package inspector (zip extraction + static analysis)
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── ui.py                # HTML routes → Jinja2 responses
│   │   └── api.py               # JSON API routes
│   │
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── extension_detail.html
│       ├── add_extension.html
│       └── help.html
│
├── static/
│   └── css/
│       └── app.css              # Gruvbox custom properties + base styles
│
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_auth.py
    ├── test_api.py
    ├── test_fetchers.py
    ├── test_inspector.py
    └── test_scoring.py
```

---

## Database Models (`app/models.py`)

### `Extension` — one row per tracked extension

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | auto |
| `store` | str | `"chrome"` / `"vscode"` / `"edge"` |
| `extension_id` | str | Store-native ID |
| `name` | str | |
| `publisher` | str | |
| `description` | str | nullable |
| `version` | str | |
| `install_count` | int | nullable |
| `last_updated` | datetime | nullable |
| `permissions` | str | JSON-encoded list |
| `store_url` | str | |
| `added_at` | datetime | |
| `last_fetched_at` | datetime | nullable |
| `watchlist` | bool | default True |
| `risk_score` | int | nullable, 0–100 |
| `risk_detail` | str | nullable, JSON breakdown per signal |
| `package_analysis` | str | nullable, JSON output from inspector |

Unique constraint: `(store, extension_id)`

### `FetchLog` — audit trail per fetch attempt

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `extension_id` | int FK | |
| `fetched_at` | datetime | |
| `success` | bool | |
| `error_message` | str | nullable |
| `risk_score_before` | int | nullable |
| `risk_score_after` | int | nullable |

### `InstallCountHistory` — for trend/drop detection

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `extension_id` | int FK | |
| `recorded_at` | datetime | |
| `install_count` | int | |

---

## Configuration (`app/config.py`)

`pydantic-settings` `BaseSettings`, env prefix `MARVIN_`:

```python
class Settings(BaseSettings):
    admin_username: str
    admin_password: str
    secret_key: str                  # itsdangerous signing key
    database_url: str = "sqlite+aiosqlite:///./marvin.db"
    session_cookie_name: str = "marvin_session"
    session_max_age: int = 86400
    fetch_interval_minutes: int = 60
    httpx_timeout: float = 15.0
```

`.env.example` with `MARVIN_ADMIN_USERNAME`, `MARVIN_ADMIN_PASSWORD`, `MARVIN_SECRET_KEY`.

---

## Auth Flow (`app/auth.py`)

**Signed cookie via itsdangerous** — no DB sessions.

- GET `/login` → render form (public)
- POST `/login` → compare with `hmac.compare_digest` (both username AND password, constant-time). On success, sign `{"u": username}` with `URLSafeTimedSerializer`, set `HttpOnly` + `SameSite=Lax` cookie. Redirect to `/`.
- POST `/logout` → clear cookie, redirect to `/login`
- `require_auth` FastAPI dependency: reads + validates cookie, redirects to `/login` on missing/expired/bad signature. Injected into every protected route.
- Generic error on bad login — no distinction between wrong username vs password.

---

## API Endpoints

### HTML routes (`/` prefix, `app/routes/ui.py`) — all protected except login

| Method | Path | Page |
|---|---|---|
| GET | `/login` | Login form |
| POST | `/login` | Auth + redirect |
| POST | `/logout` | Clear cookie |
| GET | `/` | Dashboard — extension list |
| GET | `/extensions/add` | Add extension form |
| GET | `/extensions/{id}` | Extension detail |
| GET | `/help` | Help page |

### JSON API routes (`/api` prefix, `app/routes/api.py`) — all require auth

| Method | Path | Description |
|---|---|---|
| GET | `/api/extensions` | List all |
| POST | `/api/extensions` | Add + immediate fetch |
| GET | `/api/extensions/{id}` | Single extension |
| DELETE | `/api/extensions/{id}` | Remove |
| POST | `/api/extensions/{id}/refresh` | Force re-fetch now |
| PATCH | `/api/extensions/{id}/watchlist` | Toggle watchlist |
| GET | `/api/extensions/{id}/history` | Install count history |

**`ExtensionIn`**: `{ store: "chrome"|"vscode"|"edge", extension_id: str }` — accepts full store URLs, normalised to ID internally.

**URL normalisation** helpers per store:
- Chrome: last path segment of `chromewebstore.google.com/detail/{name}/{id}`
- VS Code: `itemName` query param of `marketplace.visualstudio.com/items?itemName=...`
- Edge: last path segment of `microsoftedge.microsoft.com/addons/detail/{name}/{id}`

---

## Extension Fetchers (`app/fetchers/`)

Each fetcher does two things: fetch store metadata (popularity, publisher, dates) and download the extension package for static inspection. Both steps are attempted; a package download failure is non-fatal — metadata-only is still useful.

### Base (`base.py`)

`ExtensionMetadata` Pydantic model + `BaseFetcher` ABC with two methods:
- `async def fetch_metadata(extension_id) -> ExtensionMetadata` — store page/API
- `async def download_package(extension_id, version) -> bytes` — raw zip bytes

Shared `httpx.AsyncClient` created at startup, injected into fetchers.

### Chrome (`chrome.py`) — scraping + .crx download

**Metadata:** Fetch `https://chromewebstore.google.com/detail/{extension_id}`. Parse the embedded `AF_initDataCallback` JSON blob in a `<script>` tag for name, version, install count, last updated. Wrap all parsing in try/except and log failures.

**Package:** Download `.crx` via:
`https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0&acceptformat=crx3&x=id%3D{id}%26uc`

`.crx3` files have a binary header before the zip payload; skip the header by finding the `PK\x03\x04` magic bytes and reading the zip from that offset.

**Permissions:** Read from `manifest.json` inside the package — authoritative source, not scraped from the store page.

### VS Code (`vscode.py`) — REST API + .vsix download

**Metadata:** `POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery` with `filterType: 7` and flags `914`. Extract name, publisher, description, version, install count, last updated, publisher verification status (`publisher.isDomainVerified`).

**Package:** Download `.vsix` from the asset URL in the API response (asset type `Microsoft.VisualStudio.Services.VSIXPackage`). `.vsix` is a plain zip — no header stripping needed.

**Permissions:** Read from `extension/package.json` inside the zip (the `contributes` and `extensionDependencies` fields). Drop the store manifest fetch — the downloaded package is the authoritative source.

### Edge (`edge.py`) — scraping + .crx download

**Metadata:** Fetch `https://microsoftedge.microsoft.com/addons/detail/{extension_id}`. Parse HTML with **BeautifulSoup4**. Extract name, publisher, version, install count, last updated.

**Package:** Edge extensions use the same Chromium `.crx` format. Download via:
`https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D{id}%26uc`

Same `.crx3` header-stripping approach as Chrome.

**Permissions:** Read from `manifest.json` inside the package.

---

## Package Inspector (`app/inspector.py`)

Takes raw package bytes (zip), extracts and analyses contents. Returns a structured `PackageAnalysis` Pydantic model. All analysis is static — no code is executed.

```python
class PackageAnalysis(BaseModel):
    permissions: list[str]           # from manifest.json / package.json
    host_permissions: list[str]      # manifest v3 host_permissions field
    external_domains: list[str]      # domains found hardcoded in JS files
    uses_eval: bool                  # any eval() / new Function() calls
    uses_remote_code: bool           # fetch/XHR to non-extension origins in background scripts
    obfuscation_score: int           # 0–10 heuristic (see below)
    file_count: int
    total_size_bytes: int
    has_minified_code: bool          # any .js file >500 lines with avg line length >200
    manifest_version: int            # 2 or 3
```

### Obfuscation heuristic (0–10)

Applied to each `.js` file; take the max across all files:
- Average identifier length < 2 chars in a file with >50 identifiers → +4
- Ratio of non-ASCII or escaped unicode chars > 5% → +3
- Single-letter variable density > 60% of all identifiers → +3

### External domain extraction

Regex scan all `.js` and `.json` files for string literals matching `https?://[^/'"]+` that are not:
- The extension's own store URL
- Well-known CDNs (`googleapis.com`, `gstatic.com`, `jsdelivr.net`, `cdnjs.cloudflare.com`)
- `localhost` / `127.0.0.1`

Report all others. A high number of unknown domains is a risk signal.

---

## Risk Scoring Engine (`app/scoring.py`)

Score: **0–100** (higher = riskier). Six signals — four from store metadata, two from package inspection.

| Signal | Max pts | Source | Key logic |
|---|---|---|---|
| Permissions | 25 | Package `manifest.json` | Tiered danger list: critical (`<all_urls>`, `debugger`, `nativeMessaging`, `webRequest`) = 25; high (`cookies`, `history`, `tabs`) = 15; medium (`storage`, `notifications`) = 7 |
| Popularity | 20 | Store metadata | <100 installs = 16 pts; <1k = 8; <10k = 4; ≥10k = 0. Sudden drop >30% = +10 |
| Publisher | 15 | Store metadata | Publisher changed between fetches = +8; unverified = +4; generic name = +3 |
| Staleness | 15 | Store metadata | 3+ years = 15; 2+ = 11; 1+ = 7; 6+ months = 4; recent = 0 |
| Code behaviour | 15 | Package inspector | `uses_eval` = +8; `uses_remote_code` = +5; obfuscation_score ≥ 6 = +5; obfuscation_score ≥ 3 = +3 (capped at 15) |
| External domains | 10 | Package inspector | 0 unknown domains = 0; 1–2 = 3; 3–5 = 6; 6+ = 10 |

Unknown/null values get a moderate suspicion score (not 0, not max). If package analysis is unavailable (download failed), code behaviour and external domain signals score at their midpoint rather than 0.

**Risk level labels:**
- 0–24: `low` (Gruvbox green `#98971a`)
- 25–49: `medium` (yellow `#d79921`)
- 50–74: `high` (orange `#d65d0e`)
- 75–100: `critical` (red `#cc241d`)

Score stored on `Extension.risk_score`; breakdown stored as JSON in `Extension.risk_detail`. Recomputed on every successful fetch.

---

## Background Refresh (`app/scheduler.py`)

**APScheduler 4.x** `AsyncScheduler` with `IntervalTrigger(minutes=settings.fetch_interval_minutes)`.

Integrated into FastAPI `lifespan` context manager. On each tick: fetch all `Extension` where `watchlist=True`, re-fetch metadata, update fields, recompute score, append `InstallCountHistory`, write `FetchLog`. Errors per extension are caught and logged; one failure does not stop the rest.

Enable SQLite WAL mode at startup: `PRAGMA journal_mode=WAL`.

---

## UI / Frontend

**Styling:** Gruvbox dark CSS custom properties in `static/css/app.css`. Tailwind CDN for utility classes. JetBrains Mono via Google Fonts. AlpineJS via CDN for interactivity.

**Pages:**
- **`dashboard.html`**: Extension table with sortable columns (AlpineJS), risk score badges, per-row refresh/delete/watchlist-toggle actions. Stats bar: total tracked / high-or-critical count / last refresh time.
- **`extension_detail.html`**: Score breakdown table (all 6 signals), permissions list with danger badges, external domains list, code behaviour flags (`eval`, remote code, obfuscation level), install count sparkline (AlpineJS + inline SVG), fetch log table, "Refresh Now" button.
- **`add_extension.html`**: URL/ID input with AlpineJS auto-detection of store from pasted URL. Store radio buttons auto-select. Submits to `/api/extensions` via `fetch()`, redirects to detail on success.
- **`login.html`**: Centred card, ASCII-art tagline, generic error on failure.
- **`help.html`**: Risk score methodology, how to add extensions per store, ID format examples.

Flash messages: short-lived signed cookie (`max_age=5`), consumed on next HTML render.

---

## `requirements.txt`

```
fastapi
uvicorn[standard]
sqlmodel
aiosqlite
httpx
pydantic-settings
itsdangerous
jinja2
python-multipart
beautifulsoup4
apscheduler>=4.0
# test dependencies
respx
pytest
pytest-asyncio
```

---

## Testing

### `conftest.py`
- In-memory SQLite test DB, settings overrides
- `respx` mock for HTTPX calls (Chrome/Edge HTML responses, VS Code API JSON)
- Shared fixtures: authenticated test client, unauthenticated client, seeded extension records

### Test files
- **`test_auth.py`**: Login/logout flow, cookie validation, session expiry, protected route redirect
- **`test_api.py`**: All CRUD endpoints, duplicate detection (409), refresh trigger, watchlist toggle
- **`test_fetchers.py`**: Each fetcher with mocked HTTP (success + 404), URL normalisation helpers, mocked package download bytes
- **`test_inspector.py`**: Inspector with fixture zips — clean manifest, eval usage, obfuscated JS, external domains, `.crx3` header stripping
- **`test_scoring.py`**: Each signal function at boundary values, full `compute_risk_score` with and without package analysis

### `pytest.ini`
```ini
[pytest]
asyncio_mode = auto
testpaths = tests
```

---

## Build Order

1. `config.py` → `database.py` → `models.py` (foundation)
2. `auth.py` (depends on config)
3. `fetchers/base.py` + `fetchers/vscode.py` (real API + .vsix download, easiest to validate)
4. `inspector.py` (pure functions on zip bytes — no external deps)
5. `fetchers/chrome.py` + `fetchers/edge.py` (scraping + .crx download/header stripping)
6. `scoring.py` (pure functions, depends on inspector output shape)
7. `routes/api.py` (depends on models + fetchers + inspector + scoring)
8. `routes/ui.py` + all templates (depends on API)
9. `scheduler.py` (depends on fetchers + DB)
10. `main.py` (wires everything; lifespan = DB init + scheduler start)
11. `tests/` (written alongside each layer)

---

## Verification

- `venv/bin/python -m pytest tests/ -v` — full test suite
- `uvicorn app.main:app --reload` — manual smoke test
- Add a VS Code extension (`publisher.name`) → verify fetch, score computed, detail page renders
- Add a Chrome extension by full URL → verify URL normalisation + scrape
- Toggle watchlist off → verify excluded from next scheduler tick
- Force refresh → verify `FetchLog` entry created
- Login with wrong password → verify no cookie set, generic error shown
- Access `/` without cookie → verify redirect to `/login`
