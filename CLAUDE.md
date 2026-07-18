# IcebergEBS - Paranoid about Chrome extensions

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

### Dependency management (uv)
**Dependabot** (`.github/dependabot.yml`) opens weekly **grouped** update PRs across four ecosystems: `uv` (Python), `github-actions`, `docker` (Dockerfile base images), and `docker-compose` (the postgres/caddy pins). A Python PR updates `pyproject.toml` **and** `uv.lock` together, so `uv sync --locked` stays green. One trap worth knowing: Dependabot's Docker parser reads **`FROM` lines only** — an image referenced via `COPY --from=<image>` is invisible to it, which is why the uv binary is pulled through a named `FROM … AS uv` stage in the Dockerfile. A second trap: Dependabot does **not** parse Helm `values.yaml` image tags, so the **Helm Caddy sidecar pin** (`helm/iceberg-ebs/values.yaml` `caddy.image.tag`) has no automated update path — it's kept in lockstep with the Dependabot-managed **Compose** Caddy image by `tests/test_helm_caddy.py::test_helm_caddy_tag_matches_compose`, which fails when the two drift so a Compose bump forces the Helm bump in the same PR (#200). Bump both together.

`pyproject.toml` is the **only** dependency manifest — there is no `requirements.txt`. Runtime packages go in `[project.dependencies]`; test + static-analysis tooling goes in the **`[dependency-groups] dev`** group (PEP 735). After changing either, run **`uv lock`** and commit the updated `uv.lock`: CI installs with `uv sync --locked`, which fails on a stale lock, and the `lint` job runs an explicit `uv lock --check`. IcebergEBS is a **virtual project** (`[tool.uv] package = false`) — it is deployed as source + uvicorn, never built into a wheel, which is what lets the Dockerfile install the dependency layer from `pyproject.toml` + `uv.lock` alone. The production image builds its venv with `uv sync --frozen --no-dev`, so the `dev` group **cannot** reach the container: anything a runtime import needs must be a real runtime dependency, not a dev one.

### UI / Front end
- AlpineJS (vendored + version-pinned `@alpinejs/csp` build at `static/js/vendor/`, #85/#106 — no CDN, no eval)
- Tailwind CSS v4 (standalone CLI via `pytailwindcss`; `static/css/input.css` → gitignored `static/css/output.css`, built by `make css` / the Dockerfile `tailwind-builder` stage)
- **IcebergAI house design system** (#105): shared oklch token/component sheet `static/css/iceberg.css` (fixed glacial-cyan accent, dark `.rail` / light `.workspace` shell, `html[data-theme]` light/dark) + the app-specific layer `static/css/app.css` (risk palette + components)
- Archivo / JetBrains Mono / Spectral (self-hosted woff2 in `static/fonts/` + `static/css/fonts.css` — the family font set)


## Architecture
API-first design. All data flows through FastAPI endpoints; the UI consumes them. HTML routes render Jinja2 templates; API routes return JSON.

Per-module reference — every key module with its invariants and cross-module contracts (e.g. the mandatory commit-before-`fire_pending_alerts` ordering), plus the fetch→score→alert data flow — lives in the path-scoped rule `.claude/rules/architecture.md` (auto-loads when editing `app/**`, `tests/**`, or `alembic/**`).

## Store-specific fetcher notes
Per-store scraping/API details (Chrome/VS Code/Edge) + package inspection notes live in the path-scoped rule `.claude/rules/fetchers.md` (auto-loads when editing `app/fetchers/**` or `app/inspector.py`).

## Testing

Ensure tests are added for major functionality changes and regression tests are added where bugs are identified.

### Running Tests
The suite runs against a **real Postgres** (no SQLite). Install the locked dependency set (`uv sync`, or `make sync`), start the dev Postgres, then run pytest pointed at it:
```bash
make db   # docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres
ICEBERG_EBS_TEST_DATABASE_URL=postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs uv run pytest tests/ -v
# or simply: make test
```
`ICEBERG_EBS_TEST_DATABASE_URL` selects the test database (falls back to `ICEBERG_EBS_DATABASE_URL`).
**Host-side `uv run pytest` / `uv run alembic` / `make test` fails while `.env` carries the `POSTGRES_*` keys** (pydantic `extra_forbidden`, bug #214): comment those three lines out before the first host-side run, keep them commented for the whole work session (don't restore between rounds), and restore them when done — `docker compose up` needs them.

`pytest.ini` sets `asyncio_mode = auto` so async tests run without extra decoration. It also pins `asyncio_default_fixture_loop_scope`/`asyncio_default_test_loop_scope` to `session` because the test DB is a single **session-scoped** Postgres engine (`tests/conftest.py`) shared by all tests — fixtures and tests must run on one event loop or asyncpg raises "attached to a different loop". Per-test isolation is the autouse `_clean_tables` fixture, which `TRUNCATE … RESTART IDENTITY CASCADE`s every table after each test.

### CI gates
`.github/workflows/ci.yml` runs six **blocking** jobs on every PR + push to main: **test** (pytest, with a `postgres:18-alpine` service container + `ICEBERG_EBS_TEST_DATABASE_URL`), **lint** (`uv lock --check` + `ruff check` + `ruff format --check` over `app tests e2e` (+ `alembic` for format) + `vulture` dead-code gate, run via `uvx` — config + `vulture_whitelist.py` in `pyproject.toml`, #101), **types** (`mypy app`), **security** (`bandit -c pyproject.toml -r app` + `pip-audit`), **lint-workflows** (zizmor + actionlint over `.github/workflows/**`), and **ui** (#100 — boots the full Compose stack behind Caddy with a self-signed cert and runs the Playwright/Chromium browser smoke in `e2e/`; Playwright is installed pinned in a throwaway venv, outside `uv.lock`). The test/lint/types/security jobs install with `astral-sh/setup-uv` + `uv sync --locked` and run the tool via `uv run`. Tool config and dependencies both live in `pyproject.toml` (see Dependency management above). **All actions are SHA-pinned** with a trailing `# vN.N.N` comment and every `actions/checkout` sets `persist-credentials: false` (#96) — keep both when editing workflows, or the `lint-workflows` gate fails. A **`concurrency`** group cancels a superseded run **on PRs only** (`cancel-in-progress` gated on `github.event_name == 'pull_request'`) so a new push doesn't leave the old run's six jobs churning, while pushes to main run to completion (a cancelled main run would leave a commit with no green record); every job carries a `timeout-minutes` cap so a hung step can't burn the 6h default. Notes:
- **Ruff** selects `E,F,W,I,B` (ignores `E501`, `B008` — the FastAPI `Depends`/`Query` default idiom). Deliberately **no `UP`** (pyupgrade) to preserve the documented `timezone.utc` / `Optional[...]` conventions.
- **mypy** uses `pydantic.mypy` and enforces types only on the **pure logic / contract modules**; the ORM-query modules (`app.routes.*`, `services`, `scheduler`, `notifications`, `retention`, `database`, `fetchers.*`) are excluded via `ignore_errors` because mypy can't see through SQLModel's declarative column attributes (it reads `Extension.last_updated` as a plain `datetime`). When adding a pure-logic module, keep it type-clean rather than excluding it.
- **Bandit** benign findings are annotated inline with justified `# nosec` (git subprocess in `version.py`, best-effort file-skip loops in `inspector.py`) — keep the gate at full strictness rather than lowering severity.
- **pip-audit** runs against `uv export --no-dev` — the exact locked runtime set the production image installs, not a floating resolution. If an unfixable upstream advisory blocks CI, add `--ignore-vuln <ID>` with a justifying comment.
- **lint-workflows** (#97) is the only CI job that does **not** go through `uv run`/`uv.lock`: **zizmor** runs via `uvx zizmor@<version>` (version-pinned, not added to the `dev` group) with `GH_TOKEN` set so its online audits work; **actionlint** is installed with `go install …/actionlint@vN` (Go-checksum-database verified) rather than a third-party action. When a new zizmor/actionlint release lands, bump the pinned versions in `ci.yml`.
- Two image workflows, kept separate on purpose. **`build.yml`** (push to main) publishes **dev** images only — an immutable `:<sha>` plus a moving `:edge` pointer; there is deliberately **no `:latest`** (a mutable "deploy me" tag that, with the chart's `IfNotPresent`, ships stale code — #88). **`release.yml`** (#99) is the sole source of **deployable release** images: it fires on a `v*` SemVer tag, **verifies the tag matches `pyproject.toml`** (normalizing PEP 440 ⇄ SemVer, failing the release on mismatch), builds with **SBOM + `provenance: mode=max`**, **attests** SLSA provenance, **signs keylessly with cosign**, and cuts the GitHub Release via `gh` (a `workflow_dispatch` run is a build-only dry run). Both bake the same `ICEBERG_EBS_VERSION` string as `app/version.py:_format()`. `codeql.yml` (#98) is the SAST workflow (see Security above).

### Test structure
- `tests/conftest.py` — session-scoped Postgres engine + autouse `_clean_tables` TRUNCATE fixture, authenticated/anonymous HTTPX test clients, `make_fake_crx()` / `make_fake_vsix()` helpers, and `cached_password_hash()` — a real production-work-factor bcrypt hash computed once per distinct password per session. Use it when a test just needs a user row with a password; calling `hash_password()` per test re-pays ~250ms of bcrypt CPU each time (reserve that for tests exercising the hashing itself, e.g. `test_offload.py` / `test_auth_hardening.py`)
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
- Session cookies: HttpOnly + SameSite=Lax, signed with itsdangerous `URLSafeTimedSerializer`. Password change revokes other-device sessions + API keys (see `auth.py` note, M1). `password_changed_at` is the **generic** session cutoff since #32 — an IdP-driven `is_admin` sync bumps it too. Login is throttled app-side by `app/ratelimit.py` (M3).
- SSO (#32): OIDC client secrets are env-only (never DB/API/UI/logs — same rule as the proxy credentials); accounts are keyed on the immutable validated `(oidc_issuer, oidc_subject)` pair **scoped to the configured provider** — never the mutable email or the admin-configurable adapter key (collisions are denied, not auto-linked). The issuer stays in the key (a re-pointed adapter changes it, #218) **and** the provisioning match is scoped to `auth_provider`, so a hostile/compromised provider that spoofs another's `iss` (Authlib only checks `iss` against that provider's own discovery metadata) can't inherit its accounts — the same `(issuer, subject)` under a different provider is refused as an `"identity conflict"`, DB-backed by `uq_user_issuer_subject` (#226). SSO accounts have `password_hash IS NULL` and take the `_DUMMY_HASH` path in `verify_credentials` (always fail, constant-time); group→admin mapping defaults to non-admin and only ever syncs accounts with `role_managed_by_idp=True`, so the seeded break-glass admin is IdP-immune. The OIDC callback GET is CSRF-origin-exempt by method — its protection is Authlib's state+nonce+PKCE in the dedicated `iceberg_ebs_oidc` handshake cookie.
- **CSRF (deliberate, documented — #16):** there are **no CSRF tokens**; protection is `SameSite=Lax` (+ `Secure` in prod) on the session cookie, and the JSON API requires an `application/json` body (which browsers can't send cross-origin via a plain form) with Bearer tokens as the primary M2M credential. This is a conscious trade-off, not an oversight (see the comment in `auth.py:set_session`). **Layered on top (#107):** `app/middleware.py`'s `CSRFOriginMiddleware` enforces an `Origin`/`Referer` check on **every** state-changing browser request (each non-safe method except Bearer-token M2M) — including the unauthenticated `POST /login` that mints the cookie, so login CSRF is covered too (`origin_allowed()` matches the request host or `ICEBERG_EBS_TRUSTED_ORIGINS`). Bearer-token requests carry no browser `Origin` and are exempt. If even this needs strengthening, add per-request CSRF tokens in `set_session` + the templates rather than relying on SameSite alone.
- Never return raw exception text (`str(exc)`) to API callers on connection/SSRF paths — it can leak resolved IPs / internal hostnames. Log the detail server-side and return a generic message (M4, `alerts.py:test_destination`, `routes/proxy.py:test_proxy`). `WebhookValidationError` messages are static and intentionally user-facing, so surfacing those at create/update time is fine.
- Outbound-proxy credentials (#216) are env-only secrets: never persist them to the DB, return them from an API, render them in a template, or log a resolved proxy URL (it carries them — pass exception text through `proxy.scrub` first). The proxy connectivity test accepts only server-known target labels, never URLs (SSRF oracle), and webhook-origin targets dial the **origin only** (a Slack-style webhook path is a capability token that must not hit the wire or proxy logs on a test).

## Datetime handling
- Always use `datetime.now(timezone.utc)` — never `datetime.utcnow()` (deprecated in Python 3.12+, produces naive datetimes)
- Model `default_factory` uses the shared `_utcnow` lambda in `models.py`
- Scoring functions handle naive datetimes from external sources by attaching UTC tzinfo before comparison

## Styling, Theming and Design
The **IcebergAI house design system** (#105 — `iceberg.css` tokens/shell + `app.css` risk layer, system/light/dark theming via `theme-boot.js`, Archivo/JetBrains Mono/Spectral, IcebergAI branding, the strict `script-src 'self'` CSP in `caddy/headers.caddy` — no inline scripts, `@alpinejs/csp` build — and the `Alpine.data` registry + JSON-island pattern) lives in the path-scoped rule `.claude/rules/frontend.md` (auto-loads when editing `static/**` or `app/templates/**`). Risk-band thresholds live only in `app/scoring.py:risk_level`; band colours live only in `app.css`'s `--risk-*` tokens.

## Deployment

**Database:** **PostgreSQL only** — dev, test, and production (SQLite support was removed). Postgres' row-level locking/MVCC lets the concurrent writers (scheduler + interactive API/UI + bulk ingestion) proceed without contention and scales the history tables. All writers are commit-isolated (scheduler, retention prune, and `fire_pending_alerts` after commit). Dev runs against a containerized Postgres (`docker-compose.dev.yml` / `make dev`); the Compose/Helm stacks provision it for production; rationale lives in `DEPLOYMENT.md → Database choice`.

Full production deployment instructions are in `DEPLOYMENT.md`. Two options are covered:

**Docker Compose** — three-service stack (postgres, app, caddy). **Caddy** (config in `caddy/`, #188 — replaced nginx) terminates TLS and proxies everything — including `/static`, served by the app's StaticFiles, since the built `output.css` exists only inside the app image (#85) — to the app; it does **not** rate-limit (stock Caddy has no `rate_limit` directive), so edge throttling moved app-side (`app/ratelimit.py`, enabled via `ICEBERG_EBS_API_RATE_LIMIT_ENABLED` for `/api/*` and `ICEBERG_EBS_LOGIN_RATE_LIMIT_ENABLED` for `POST /login`, #196). Caddy sets `X-Forwarded-For` to a single canonical `{client_ip}`, discarding a client-supplied XFF at the edge (#77). Single uvicorn worker required (APScheduler is per-process; multiple workers produce duplicate watchlist refreshes and `AlertLog` rows).

**Kubernetes (Helm)** — chart under `helm/iceberg-ebs/` with Bitnami postgresql subchart. `replicaCount: 1` is mandatory for the same reason. Topology is **cluster nginx-ingress-controller (TLS via cert-manager, edge rate limiting) → in-pod Caddy sidecar (:8080) → app (localhost:8000)** (#188): the sidecar owns the canonical security headers via the `caddy` ConfigMap (a test-guarded mirror of `caddy/Caddyfile.k8s` + `caddy/headers.caddy` — Helm can't read files above the chart), so the ingress no longer carries a duplicated CSP snippet. Editing the edge config means editing `caddy/` and re-mirroring the ConfigMap; `tests/test_helm_caddy.py` + `tests/test_csp_strict.py` fail on drift.

Quick start (Docker):
```bash
bash caddy/generate-dev-cert.sh
cp .env.example .env && $EDITOR .env
docker compose up --build
```

## Versioning
IcebergEBS carries **two** identifiers, shown together at the bottom of the left rail as `v{semver} · build N · sha` (e.g. `v0.1.0b1 · build 74 · 8823e7a`). They answer different questions and must not be conflated:
- **SemVer** (`0.1.0b1`) is the **release** version — the only thing that can express a breaking change, and what an API/SOAR consumer pins. Single source of truth: **`[project].version` in `pyproject.toml`**, read at runtime by `app/version.py:_semver()` via stdlib `tomllib` (never hardcoded, never duplicated). Git tags use the **SemVer spelling** of the same value (`0.1.0b1` ⇄ tag `v0.1.0-beta.1`) — the PEP 440 / SemVer mapping and the release procedure live in **`docs/RELEASING.md`**; changes are recorded in **`CHANGELOG.md`** (Keep a Changelog).
- **`build N · sha`** is the **build** identifier (`N` = `git rev-list --count --first-parent HEAD`, +1 per merge to main). It advances on every merge and is *not* a release.

Resolved by `app/version.py:get_version()` (cached once per process) in priority order: `ICEBERG_EBS_VERSION` env → stamped `app/_version` file (git-ignored) → runtime git + pyproject → `"dev"`. The first two carry a complete string and so win **wholesale**. Injected into every page via `_render()` in `app/routes/ui.py`, rendered in the `rail_footer` block (`.rail-version` in `app.css`).
- **Bumping the version requires `uv lock`.** `uv.lock` records the project's *own* version, so a `pyproject.toml` bump without a lock refresh fails CI's `uv lock --check`. This is the most common way to break the build here.
- `_semver()` **never raises** — a missing or malformed `pyproject.toml` degrades to the bare `build N · sha`. It runs on every page render, so it must not be able to 500 the UI.
- **Auto-increment:** on the bare-uvicorn droplet (a git checkout) the number advances on each `git pull` of main — no manual bump.
- **No `.git` (Docker/Helm):** `.dockerignore` strips `.git`, so the image relies on the `ICEBERG_EBS_VERSION` env (Dockerfile `ARG`/`ENV`). The `.github/workflows/build.yml` workflow computes the same string and passes it as `--build-arg ICEBERG_EBS_VERSION`. It checks out with `fetch-depth: 0` — required, or `rev-list --count` is wrong on Actions' shallow clone.
- Keep the format string in sync between `app/version.py:_format()` and the version-compute step in **both** `build.yml` and `release.yml` — all read the SemVer from `pyproject.toml`. A drift is invisible until a container deploy reports a different version from the droplet.
- **Releasing (#99):** pushing a `v*` SemVer tag triggers `release.yml`, which **verifies the tag matches `pyproject.toml`** (normalizing PEP 440 ⇄ SemVer, failing on mismatch), then builds a signed + attested release image (SBOM, SLSA provenance, cosign keyless) and cuts the GitHub Release. Release images — not `build.yml`'s `:edge`/`:<sha>` dev images — are the only deployable, verifiable artefacts; pin them by immutable tag/digest. Full procedure + `cosign verify` / `gh attestation verify` flow in `docs/RELEASING.md`.

## Contributing & the review bot
Merges to `main` go through the **`icebergai-review-bot`** (an automated reviewer) and `main` is protected — you cannot push to it directly. Hard-won notes on working with it:

**How the bot behaves**
- Reviews the full `main...HEAD` diff, posts an **"IcebergAI Review Bot"** check-run plus a PR review with a verdict (`approve` / `request_changes`), and **merges the PR itself on approval**.
- It **auto-closes the linked issue only from a `Closes #N` keyword in the PR _body_.** A `(#N)` in the PR _title_ is a cross-reference, **not** a closing keyword — the issue stays open. Always put `Closes #N` in the body, then after merge **reconcile**: confirm the issue actually closed, and if a title-only reference left it open, close it manually with a comment linking the merged PR.
- It re-reviews **every new head SHA** and compares files by **blob SHA across heads** — a rebase that leaves a file's blob unchanged makes it re-raise the identical finding. Fix the code; a rebase alone won't clear a real finding.
- Its findings are usually real. On a `request_changes` P1, fix the root cause **and add the regression test it asks for** rather than pushing back — it keeps blocking until the concern is genuinely addressed (e.g. #109 escalated through three distinct P1s: pending-alert overwrite → fake shutdown drain → non-atomic merge/clear race). #217 repeated the pattern on a settings invariant (route pre-check TOCTOU → row lock reading a stale identity map → fixed): on a **concurrency/invariant** finding, jump straight to the strongest enforcement in one round — a schema CHECK constraint **plus** a locked read that actually refreshes: `session.get(..., with_for_update=True, populate_existing=True)` (without `populate_existing` SQLAlchemy returns the already-loaded instance with stale attributes, so the queued writer validates pre-commit state). #218 (SSO) added two more: **key an identity on the validated authority** (the OIDC `iss` claim), never a configurable proxy for it (the adapter key), and **enforce the uniqueness invariant with a DB partial unique index**, not just an app-level check that two concurrent first-logins can both pass; and a migration **downgrade must never delete user rows** to satisfy a restored NOT NULL — backfill an unusable-but-valid sentinel (e.g. a bcrypt hash of a discarded random secret) or refuse, and verify **up→down→up on a scratch DB** (host has no `psql` — run it via `docker exec <postgres-container> psql`).
- **Runtime is flaky:** it can throw a RuntimeError ("…will be retried") and auto-retry, and a verdict can briefly oscillate or stall. Wait it out — do **not** push to "un-stick" it.
- **"Dismiss stale reviews on push" is ON.** Any push — including an empty "nudge" commit — dismisses a fresh approval, and a nudge can race an incoming approval webhook and cancel it. **Never push to an approved (or freshly reviewed) PR unless you have a real change to make.**

**Branch & PR hygiene**
- One issue per branch, branched from **latest `main`** — **never stack PRs.** GitHub's *documented* default is to **retarget** an open PR to its base's base branch when the base branch is deleted on merge ([docs](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/merging-a-pull-request)), but stacking is fragile in practice: in this repo **#138 was auto-closed** (not cleanly retargeted) when its stacked base — the #108 PR branch — was deleted on merge, silently losing the work. Branch every PR from `main` so a base merge can't strand it.
- Clear `mergeable_state: behind` by rebasing onto `main`. Recurring conflicts land on the append-only shared files (`CHANGELOG.md`, `CLAUDE.md`, `DEPLOYMENT.md`) — resolve by keeping **both** entries in order, not by dropping one side.
- `mergeable_state` cheatsheet: `clean` = ready to merge · `blocked` = missing the required bot review · `behind` = base moved, rebase · `unstable` = a non-required check (often the bot review itself) still running.

**Running many PRs efficiently**
- CI reruns on every push and must be **green before the bot reviews**. Validate locally first when feasible (per the Testing section — a real Postgres 18 + a venv installed from `pyproject.toml`) rather than spending review rounds on avoidable CI failures.
- Monitor with the PR-activity subscription / webhooks; pace status checks, don't tight-poll for events that arrive as notifications.

## Maintenance
- Keep this file up to date with decisions around structure, architecture, and function.
- Ensure the application's help page (`app/templates/help.html`) is up to date and accurate.
