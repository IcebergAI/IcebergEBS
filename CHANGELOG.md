# Changelog

All notable changes to IcebergEBS are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note the two spellings of the same version: `pyproject.toml` carries the **PEP 440**
form (`0.1.0b1`) and the git tag carries the **SemVer** form (`v0.1.0-beta.1`). The
headings below use the SemVer form. See [docs/RELEASING.md](docs/RELEASING.md).

The running build also reports a build identifier — `v0.1.0b1 · build 74 · 8823e7a` —
where `build N · sha` identifies the exact commit. That is a *build* identifier, not a
release version; only the SemVer part appears here.

## [0.1.0-beta.1] — unreleased

First beta. Everything below is the work merged to `main` to date; there is no earlier
release to diff against.

### Added

- Extension tracking for the **Chrome Web Store, VS Code Marketplace, and Edge Add-ons**:
  metadata fetch, package download, and static analysis of the shipped code.
- **Risk scoring** (0–100) across permissions, popularity, publisher identity, staleness,
  code behaviour (eval/obfuscation/remote fetches), and external domains contacted.
- **Multi-user watchlists** with a background scheduler that re-fetches on an interval and
  fires **webhook alerts** when an extension changes.
- Pagination, filtering, search, and sorting on `GET /api/extensions` and the dashboard (#23).
- **Bulk import** — `POST /api/extensions/bulk`, plus a paste box in the UI (#24).
- **Export** — `GET /api/extensions/export?format=csv|json` (#25).
- **SOAR-fed org inventory and exposure** — `POST /api/inventory`, an install footprint per
  extension, and exposure ("blast radius") = risk × footprint, surfaced as a top-exposure
  panel and a per-department breakdown (#29).
- **Fetch-health surfacing** on the dashboard, plus unauthenticated `/healthz` (liveness)
  and `/readyz` (readiness) probes for orchestrators (#26).
- **Data retention pruning** for `FetchLog`, `InstallCountHistory`, and `AlertLog`, gated by
  `ICEBERG_EBS_RETENTION_DAYS` (#22).
- **API keys** (bearer tokens, read-only supported) for machine-to-machine access.
- **Database backups** — the Docker Compose stack ships a `backup` service that writes retained,
  atomically-written `pg_dump -Fc` dumps to `./backups` on a configurable cadence
  (`BACKUP_INTERVAL_SECONDS`/`BACKUP_RETENTION_DAYS`), plus a restore runbook, pre-upgrade dump step,
  Helm backup options (Bitnami CronJob / VolumeSnapshots / external managed Postgres), and an explicit
  RPO in `DEPLOYMENT.md → Backups & disaster recovery` (#86).
- A **browser-level UI smoke** CI job (`ui`) — boots the real stack (Postgres + uvicorn behind nginx
  with `security_headers.conf`) and drives it with Playwright: login → dashboard renders → topbar
  search, asserting no CSP violation or uncaught JS error. This catches breakage the API/unit suite
  can't see — most importantly the hand-maintained inline-script CSP hash drifting. Playwright runs
  from a throwaway venv, so it needs no `uv.lock` entry (#100).
- **Observability baseline** (#89) — application logs now carry a **timestamp** (and can be emitted as
  single-line **JSON** via `ICEBERG_EBS_LOG_JSON=true`, forwarded by both deploy stacks, covering the
  app + uvicorn loggers); **`/readyz` reports
  `last_scheduler_run`** (an in-process signal — no history-table scan on the probe, scheduler-only so an
  API fetch can't mask a stall) so an external monitor can catch "the app is up but the scheduler has
  stalled" (advisory — it doesn't flip readiness); and the nginx access log gains
  **referer, user-agent, and request/upstream timing**. Error-tracking (Sentry) is a documented
  follow-up (it needs a runtime dependency).

- **Outbound proxy support for all egress** (#216) — store metadata fetching, package
  downloads, and webhook alert delivery route through a configurable forward proxy. Three
  modes (`system` — honour `HTTP(S)_PROXY`/`NO_PROXY` env; `none` — always direct;
  `explicit` — configured proxy URL with standard NO_PROXY semantics incl. CIDR ranges),
  seeded from `ICEBERG_EBS_PROXY_*` env into an admin-editable routing config at
  `/admin/proxy` (applies from the next request, no restart), with an SSRF-safe
  connectivity test over server-known egress targets only. Proxy credentials are
  env-only — never persisted, returned by the API, or logged. Webhook delivery keeps its
  IP-pinning SSRF defence through the proxy (IP-literal `CONNECT`).
- **Single sign-on via OIDC** (#32) — Authorization Code + PKCE (Authlib) against
  **Microsoft Entra ID, Authentik, Auth0, or Okta**, with just-in-time account
  provisioning keyed on the immutable provider subject (a mutable email claim can never
  claim an existing account — collisions are denied, not auto-linked), and IdP
  group→admin mapping via a per-provider `group=admin|user` allowlist (default
  non-admin, no self-elevation; the flag re-syncs on every SSO login and revokes older
  sessions on change). `ICEBERG_EBS_AUTH_MODE` gates the login paths
  (`local`/`oidc`/`both`) with local accounts as break-glass — OIDC-only mode is refused
  unless a complete provider is enabled. Non-secret provider config is env-seeded and
  admin-editable at `/admin/oidc`; client secrets are env-only, never persisted,
  returned, or logged. All IdP traffic routes through the #216 proxy layer. IdP
  group→named-role mapping (`analyst` etc.) lands with RBAC (#33); SAML, an explicit
  account-linking flow, and RP-initiated logout are follow-ups.

### Changed

- **Two static-inspector false positives no longer inflate scores** (#151): a bare
  `new XMLHttpRequest` constructor no longer counts as remote code (only a `.open(...)` to a
  literal `http(s)://` URL does — matching how `fetch()` was already scored), and a *scoped*
  wildcard-subdomain CSP source like `https://*.googleapis.com` is no longer flagged as a broad
  wildcard (only a whole-host wildcard — bare `*`, `https://*`, `https://*:443`, `https://*/path`
  — is). Benign extensions that hit either pattern re-score lower on their next refresh, which can
  move a `risk_level` band. (The legacy duplicate `_REMOTE_FETCH_RE` — which drove the bare-XHR
  path — is removed.)
- **External-domain scoring now counts distinct registrable domains (eTLD+1)** via
  the Public Suffix List (`tldextract`, pinned to its bundled offline snapshot — no
  network or disk access), not raw hostnames (#254): a single party spraying
  subdomains (`api.`/`cdn.`/`ws.evil.com`) no longer outscores genuinely unrelated
  sites. Existing extensions may re-score lower on their next refresh, which can move
  a `risk_level` band and fire a `risk_level_change` alert once. Stored/displayed
  domain lists and threat-intel indicators still carry the full hostnames.
- **Outbound `HTTP(S)_PROXY` env vars are now honoured by default** (#216): the shared
  httpx client previously ignored them entirely (custom transport). The new default
  proxy mode `system` applies them — set `ICEBERG_EBS_PROXY_MODE=none` to keep the old
  always-direct behaviour.
- **Legacy design tokens fully retired** (#212): the ~250 inline `style="…var(--ink-N)…"`
  attributes left from the pre-house design are swept to the house token names and the
  `app.css` alias bridge is deleted; `tests/test_design_tokens.py` guards against legacy
  tokens or stray oklch severity literals reappearing in templates/JS.
- **Account menu moved to the rail foot; `/` focuses search** (#223): the user/theme menu
  relocated from the topbar to the bottom of the left rail, and pressing `/` (outside a text
  field) jumps to the topbar search box, with a `/` hint chip shown in it.
- **Adopted the IcebergAI house design system** (#105): the shared family token sheet
  (`static/css/iceberg.css` — cool blue-grey oklch palette, fixed glacial-cyan accent, dark
  `.rail` / light `.workspace` / `.brandbar` shell) replaces the bespoke "Refined Operator"
  theme; `app.css` shrank to the app-specific layer (risk palette + components) with the old
  `--ink-N` scale aliased onto house tokens. Fonts moved from IBM Plex to the family set —
  **Archivo** (UI), **JetBrains Mono** (data/labels), **Spectral** (prose), self-hosted. The
  Aperture mark is retired for the **IcebergAI** brand mark (rail lockup, login, favicons),
  and the login page became the house centered auth-card. **Risk-band colours are
  consolidated**: the 75/50/25 thresholds live only in `app/scoring.py:risk_level` (the
  server passes `risk_band` to the UI) and the severity colours live only in `app.css`'s
  `--risk-*` tokens — the duplicated oklch literals in the dashboard JS, detail-page Jinja
  and `trend-chart.js` are deleted, and the trend chart now follows the light/dark theme.
- **Strict same-origin Content-Security-Policy** (#106): `script-src` is now exactly `'self'` —
  no CDN hosts, no `unsafe-eval`, and **no inline scripts anywhere**. Alpine moved to the
  **`@alpinejs/csp` build** with every component registered via `Alpine.data()` from
  same-origin files (`static/js/app.js` + `static/js/pages/`), server data delivered through
  `<script type="application/json">` islands, and the hash-pinned inline anti-flash script
  replaced by the external `static/js/theme-boot.js` — deleting the hand-maintained sha256
  pin entirely. Theme preference upgraded from a binary toggle to **system/light/dark**
  ('system' follows the OS via `prefers-color-scheme`), cookie-backed for flicker-free
  server-side first paint. Guards: `tests/test_csp_strict.py` (no inline scripts/handlers,
  script-src exactly `'self'`) and the e2e suite now fails on **any** CSP console error.
  This also **fixes Alpine interactivity in production**: behind Caddy the old standard
  build's expression eval was CSP-blocked (no `unsafe-eval`), so interactive components
  (dropdown, tabs, forms' client behaviour) silently didn't run.
- **The frontend is fully self-hosted — no third-party CDN at runtime** (#85). Tailwind is now
  a real v4 build (standalone CLI via `pytailwindcss`, `static/css/input.css` → a gitignored
  `static/css/output.css`, built by `make css` / a Dockerfile `tailwind-builder` stage) instead
  of the browser-compiled Play CDN; Alpine.js is vendored and version-pinned
  (`static/js/vendor/alpine-3.15.12.min.js`) instead of a floating `3.x.x` from jsDelivr; the
  IBM Plex fonts are served from `static/fonts/` instead of Google Fonts (also a privacy fix —
  visitor IPs no longer leak to Google). The Play-CDN config shim `static/js/tailwind-config.js`
  is retired. Compose's Caddy now proxies `/static` to the app (like the K8s sidecar) since the
  built CSS exists only inside the app image; the CSP drops `cdn.tailwindcss.com`,
  `cdn.jsdelivr.net`, `fonts.googleapis.com` and `fonts.gstatic.com` — every source directive is
  same-origin, enforced by `tests/test_no_third_party_origins.py`.
- **Replaced nginx with [Caddy](https://caddyserver.com) as the edge reverse proxy** (#188).
  The canonical security headers — CSP (with its inline-script hash), HSTS, and the rest — now
  live in **one** place, `caddy/headers.caddy`, imported by both the Compose Caddyfile and the
  Kubernetes sidecar config; previously the CSP was hand-duplicated across
  `nginx/security_headers.conf` and the Helm ingress snippet, and the two copies had drifted.
  The Kubernetes topology is now **cluster ingress → in-pod Caddy sidecar → app**, so the
  ingress no longer carries a duplicated CSP snippet. Because Caddy has no built-in rate-limit
  directive, the old nginx `login`/`api` `limit_req` zones moved **app-side**: a new token-bucket
  API rate limiter (`ICEBERG_EBS_API_RATE_LIMIT_ENABLED`, on in the Compose/Helm env) keyed on
  the client IP, with the K8s cluster ingress still limiting at the true edge. The
  `X-Forwarded-For` anti-spoof (#77) is preserved — Caddy sets a single canonical `{client_ip}`,
  discarding a client-supplied XFF at the edge and honouring the ingress's value in-cluster.
- **Postgres pinned to `18-alpine`** (was `16-alpine`), bumped together across the Compose server,
  the `backup`/`pg_dump` service, and the CI test service container so `pg_dump`'s version always
  matches the server's. An existing PG16 `postgres_data` volume will **not** start under 18 — see
  `DEPLOYMENT.md → Backups & disaster recovery` for the dump/restore upgrade path (a fresh install
  needs nothing). nginx bumped `1.29-alpine` → `1.31-alpine`. Supersedes the grouped Dependabot
  PR #114, which changed only the Compose server image.
- **Renamed from Marvin to IcebergEBS**, ahead of the repository being made public. This
  renames the product, the repository (`IcebergAI/IcebergEBS`), and the internal
  identifiers: the config env prefix is now **`ICEBERG_EBS_`** (was `MARVIN_`), the default
  Postgres user/database is `iceberg_ebs`, the session cookie is `iceberg_ebs_session`, API
  keys are prefixed `ebs_`, and the webhook payload field `marvin_url` is now
  `iceberg_ebs_url`. There was no released version and no deployment to migrate, so no
  compatibility shim is carried.
- **PostgreSQL is now the only supported database** — SQLite support removed, in dev, test,
  and production (#27).
- Schema is managed by **Alembic** instead of hand-rolled migrations (#11).
- Dependencies are managed with **uv against a committed `uv.lock`**; `pyproject.toml` is the
  single manifest and builds are reproducible (#90).
- The production image is **multi-stage and runtime-only** — no build tooling, no uv, and no
  test toolchain in the deployed container (#84).
- **Dependabot** watches Python packages, GitHub Actions, and container images weekly (#91).
- CPU-bound work (bcrypt, package inspection) is offloaded off the event loop, so a single
  worker no longer stalls on it (#4).
- `ApiKey.last_used_at` writes are throttled instead of committing on every bearer request (#5).
- The extension list endpoint no longer builds threat-intel indicators it never renders (#12).
- Inventory scoring of unknown extensions is deferred to the scheduler, so a large SOAR batch
  cannot exceed the request timeout (#78).
- **Outbound-fetch resilience** — the shared HTTP client now retries transient store failures
  (connect/timeout/429/5xx) on idempotent requests (GETs, plus the VS Code gallery query, a read
  served over POST that opts in) with exponential backoff + jitter, honouring `Retry-After`, and
  bounds its connection pool; 404 (a delisted extension) is never retried, and webhook POSTs are
  never retried. A per-store **circuit breaker** stops hammering a store that fails repeatedly in a
  cycle and records the skip as a *store outage* (new `FetchLog.store_outage`) so the Fetch-health
  tile no longer blames every extension when a store is simply down; unexpected internal errors
  (not store failures) stay loudly logged and never open the circuit (#108).
- Each refresh now loads only the two most recent install-count readings instead of hydrating an
  extension's entire history — the sudden-drop scoring check only needs the previous reading, so the
  old full-table scan grew unboundedly (retention is disabled by default) on every refresh of every
  watchlist extension (#146).
- The shared **`get_alert_log`** query/serialization helper moved out of the `routes/alerts.py`
  HTTP-route module into a neutral `app/alert_queries.py`, so the dashboard (`routes/ui.py`) no
  longer reaches cross-module into a route module for it. Pure code motion, no behaviour change —
  mirrors how the extension-query layer was pulled into `app/extension_queries.py` (#149).

### Fixed

- **Static analysis is no longer evadable by renaming a file** (#275). The code-behaviour scan
  selected files with `name.endswith(".js")`, but Chrome loads whatever path the manifest points
  at and a VS Code `main` is routinely `.cjs`/`.mjs`. A payload in `bg.mjs` — or in a file the
  manifest names `core.dat` — was never read, so it reported no eval, no remote code, an
  obfuscation score of 0 and no external domains: *lower* code-behaviour and network scores than
  an extension whose package could not be downloaded at all, which gets the unknown-midpoint.
  MV2 `background.page` HTML with an inline `<script>` was invisible for the same reason. The
  scan now covers the `.js`/`.mjs`/`.cjs`/`.jsx` and HTML suffixes **plus** every path the
  manifest references as executable (service worker, background scripts/page, content scripts,
  popup/options/devtools/sandbox pages, VS Code `main`/`browser`), whatever it is called. HTML
  pages have their script boundaries resolved by a real parser (BeautifulSoup) rather than a
  regex — `</script foo>`, a `</script>` inside a string literal and a `<script>` inside an HTML
  comment all behave in ways a pattern match gets wrong, either hiding a payload or inventing a
  finding for code the browser never runs — and the page is then masked down to those script
  bodies so line numbers stay accurate and markup never reaches the minification/obfuscation
  heuristics. A remote `<script src>` in a packaged page is flagged `remote_script_include`
  (critical) with its host recorded as an external domain.
- **A missing credential now aborts `docker compose up` instead of starting a broken stack.**
  `docker-compose.yml` referenced `${POSTGRES_PASSWORD}` (and the admin/secret vars) bare, and
  Compose resolves an unset variable to the empty string behind a warning that scrolls past in
  `up` output — so the stack started and failed later, inside the app, as an
  `asyncpg.InvalidPasswordError` that reads like a code or networking fault rather than a
  missing variable. All credential references now use `${VAR:?message}` and name the variable
  on failure, matching the Helm chart's existing `| required`. Note only `SECRET_KEY` had an
  app-side validator, so an empty `ICEBERG_EBS_ADMIN_PASSWORD` previously seeded a passwordless
  admin without complaint.
- **`docker-compose.dev.yml` no longer hardcodes credentials**, so there is a single source.
  It previously set `POSTGRES_PASSWORD: iceberg_ebs` and a full `ICEBERG_EBS_DATABASE_URL`,
  which made `make dev` succeed on a machine where a plain `docker compose up` failed with the
  same `.env` — the dev path silently masked the misconfiguration that broke every other path.
  Dev now inherits `.env` through the base file and overrides only `ICEBERG_EBS_SECURE_COOKIES`.
  Consequence: `make dev` now requires a populated `.env`.
- **`make test` follows a rotated password.** The `Makefile` hardcoded
  `iceberg_ebs:iceberg_ebs@localhost` in `TEST_DATABASE_URL`; it now derives the URL from the
  `.env` `POSTGRES_*` values via `-include .env`.
- Documented the two config traps that made this expensive to diagnose: `POSTGRES_PASSWORD` is
  read **only when the data volume is first created** (editing `.env` against an existing volume
  silently keeps the old password — rotate with `ALTER USER`, see `DEPLOYMENT.md`), and
  host-side pytest needs `ICEBERG_EBS_DATABASE_URL` rather than `ICEBERG_EBS_TEST_DATABASE_URL`
  in `.env`, because `conftest.py` reads the latter from `os.environ`, which `.env` never
  populates. Guarded by the new `tests/test_compose_secrets.py`.
- **Frontend polish** (#237): the `/` search shortcut no longer fires on a modifier combo
  (Ctrl/Cmd/Alt+`/`) or mid-IME-composition; the dashboard's per-row **Refresh** reports a
  failure inline instead of an unhandled promise rejection + `alert()`; and the bulk-import
  button shows an honest "Importing N…" label instead of a fake `0/N` progress counter.
- **Proxy `mode` is now constrained to the exact enum, case-insensitively** (#230). The
  `ProxySettings.mode` CHECK only enforced the EXPLICIT⇒URL rule and was case-sensitive, and
  `update_settings` compared case-sensitively too — so a writer bypassing the route validator (raw
  SQL, a migration backfill, or a direct `update_settings({"mode": "explicit"})`) could commit
  `mode='explicit'` with an empty URL past both guards, which the resolver treats as EXPLICIT-with-
  no-URL → **direct egress**, the fail-open state the guards exist to prevent. Added a
  `CHECK (mode IN ('NONE','SYSTEM','EXPLICIT'))` constraint (new migration, with defensive
  normalisation of any pre-existing bad rows) and made `update_settings` normalise/validate the mode
  case-insensitively, mirroring the `OIDCSettings.auth_mode` guard (#218).
- **`ICEBERG_EBS_TRUSTED_ORIGINS` is now configurable in both deploy stacks** (#153). The CSRF
  origin check's trusted-origins setting (#107) — for proxies that rewrite `Host` — was not
  forwarded by the Compose `app.environment` block, had no Helm value/ConfigMap entry, and was
  absent from `.env.example`. Since `.env` is excluded from the image, an operator setting it got
  nothing, and a proxy that rewrites `Host` would 403 every browser POST (including login) with no
  supported fix. Wired through docker-compose, the Helm ConfigMap + `values.yaml`, and
  `.env.example` (defaulting empty), guarded by `tests/test_deploy_env.py`.
- **Following `.env.example` no longer crashes startup** (#214). The shared `.env` that
  `.env.example` tells operators to fill carries the Compose stack's non-prefixed
  `POSTGRES_DB`/`POSTGRES_USER`/`POSTGRES_PASSWORD` keys, which pydantic-settings rejected as
  forbidden extras — breaking bare-uvicorn / `make test` local runs (Compose was unaffected, as
  it passes explicit `ICEBERG_EBS_*` env). `Settings` now uses `extra="ignore"`, so non-app dotenv
  keys are dropped instead of aborting import.
- **SSO no longer silently demotes IdP-managed admins in large Entra tenants** (#227). When an
  Entra user is in more than ~200 groups, the ID token omits the `groups` claim and emits the
  distributed-claims pointers `_claim_names`/`_claim_sources` instead (the "groups overage"
  contract). The adapter read the absent claim as "no groups", so `map_is_admin` returned `False`
  and the returning-user sync demoted the admin and bumped `password_changed_at` — revoking all
  their sessions, silently, on an otherwise-successful login. `EntraAdapter` now detects the
  overage/distributed-groups condition and **fails the login closed** with a logged, operator-
  actionable reason (redirect to `/login?error=sso`) instead of syncing an empty group list, so
  the admin's role and sessions are left untouched. The overage indicator is always keyed on
  `groups` in `_claim_names`, so the guard covers both the `groups` claim and the `emit_as_roles`
  configuration (`role_claim="roles"`); an inline value is trusted over the pointer. Regression
  tests cover the overage payloads.
- **Variable fonts are shipped as one file per family+subset instead of byte-identical
  per-weight copies** (#236). `static/fonts/archivo-*` and `jetbrains-mono-*` were 10 and 8
  byte-identical copies of a single wght-axis *variable* woff2 each — every weight fetched the
  same bytes over a distinct URL (~130KB+ of duplicate transfer per family). Each family now
  ships one file per subset (`archivo-normal-{latin,latin-ext}.woff2`,
  `jetbrains-mono-normal-{latin,latin-ext}.woff2`) declared by a single `@font-face` per subset
  with a `font-weight` *range* descriptor (Archivo `100 900`, JetBrains Mono `400 800`), halving
  both `static/css/fonts.css` and the font downloads. Spectral ships as static per-weight
  instances and is unchanged.
- **The API/login rate-limit tuning knobs are now forwarded and documented** (#202). The
  `*_RATE_LIMIT_PER_MINUTE` / `*_RATE_LIMIT_BURST` settings existed in `app/config.py` but were
  not forwarded by the Compose stack or the Helm ConfigMap and were absent from `.env.example`, so
  an operator setting them got the defaults silently (the same `.env`-excluded-from-image trap as
  #87). All four are now wired through `docker-compose.yml`, the Helm ConfigMap + `values.yaml`,
  and `.env.example`, added to the DEPLOYMENT.md env table, and guarded by `tests/test_deploy_env.py`.
  The Helm Deployment also now hashes the app ConfigMap into a pod-template `checksum/config`
  annotation (it previously hashed only the Caddy ConfigMap), so a `helm upgrade` that changes a
  forwarded value actually rolls the pod — otherwise the new value, loaded once via `envFrom`,
  would not take effect on the running pod until a manual restart.
- **Closed two holes in the "exactly one canonical security header" guarantee** (#201). (1) The
  Kubernetes ingress carried `nginx.ingress.kubernetes.io/hsts: "false"`, which isn't a real
  ingress-nginx annotation (HSTS is a controller-wide ConfigMap setting), so it was silently
  ignored — on a default controller its own weaker, non-preload HSTS overrode the Caddy sidecar's
  canonical one. The non-annotation is removed and DEPLOYMENT.md now documents disabling HSTS at
  the controller ConfigMap. (2) `caddy/headers.caddy` relied on an *implicit* `defer` (triggered
  only because the block contains the `-Server` delete op) to apply its header SETs after
  `reverse_proxy` copies the upstream baseline headers; a future edit dropping `-Server` would
  have silently shipped two CSP/HSTS values. An explicit `defer` now makes that robust. Neither
  was a security regression (all values enforce HTTPS), but both defeated the single-copy intent
  of #188. Guarded by new `tests/test_helm_caddy.py` assertions.
- **The Helm Caddy sidecar pin no longer silently drifts from the Compose one** (#200). The Helm
  `values.yaml` Caddy image was pinned at `2.8-alpine` while Dependabot had already moved the
  Compose image to `2.11-alpine`, and a comment falsely claimed "Dependabot's docker ecosystem
  keeps it current" — but Dependabot doesn't parse Helm values, so the two production edge proxies
  ran different (CVE-accumulating) versions with no update path. The Helm tag is realigned to
  `2.11-alpine`, and a new `tests/test_helm_caddy.py::test_helm_caddy_tag_matches_compose` fails
  whenever the Helm and Compose Caddy tags diverge, so a Dependabot Compose bump now forces the
  Helm bump in the same PR.
- **An aborted test run no longer leaves the dev database unbootable** (#199). The #113 fix drops
  `alembic_version` in the test setup, so during a run the dev DB holds a `create_all`'d head
  schema with no stamp. If the suite was aborted before teardown, the next `make dev` boot
  misclassified that head schema as a *pre-Alembic baseline*, stamped the baseline, and re-ran
  the post-baseline migrations against columns `create_all` had already made — failing with
  `DuplicateColumn`. Adoption now compares the unstamped schema against the current models: an
  exact match (== head) is stamped at *head*, making the boot a no-op; an unstamped schema that
  is post-baseline but does **not** match head (an aborted run from an *older* checkout, then the
  code updated) is refused with a clear "drop the dev database" error rather than stamped at head
  and silently skipping the intervening migrations. Inert in production (never runs `create_all`).
- **The at-startup retention prune is no longer silently skipped as a misfire** (#198). The prune
  job fires at startup (#145) via `next_run_time=now`, but relied on APScheduler's default 1-second
  `misfire_grace_time`: a >1s gap between the scheduler being created and the executor picking the
  job up — a CPU-starved container start, exactly the restart-churn #145 targets — dropped the
  startup prune as a misfire, so nothing pruned until +24h. Both scheduler jobs now set
  `misfire_grace_time=None`, so a due fire runs however late the loop is (coalesced to one run)
  rather than being skipped.
- **A corrupt pending-alert marker can no longer loop forever or crash a refresh** (#197). The
  durable `pending_alert_events` marker (#109) is now decoded in one place
  (`services._parse_pending_events`), which drops both non-dict entries and malformed event dicts
  instead of raising. Two failure modes are closed: (1) a marker holding a valid event next to
  non-dict junk delivered the valid event but then compare-and-cleared against the *filtered*
  subset — which never matched the raw marker — so the alert re-fired on **every** scheduler cycle
  forever (recovery now clears against the raw marker); (2) a valid-JSON-but-wrong-shape marker
  (e.g. `"{}"` or `["junk"]`) raised `TypeError` inside `_merge_pending_events`, 500-ing the
  refresh and blocking every future refresh of that extension until the marker was hand-fixed.
  Both require an externally corrupted marker (the app only ever writes lists of dicts), but the
  new terminal-clear/cleanse behaviour is self-healing.
- **Restored the per-IP rate limit on `POST /login`** that the nginx→Caddy migration dropped
  (#196). The old nginx `login` `limit_req` zone capped login POSTs at 5/min per IP; the Caddy
  migration replaced only the `api` zone app-side, leaving `POST /login` uncapped in the Compose
  deployment. Because `POST /login` pays the ~100ms bcrypt cost even for unknown usernames, an
  unthrottled flood was both a CPU-DoS on the single worker and a username-spray vector that the
  failure-keyed `(IP, username)` lockout can't stop. A tighter token-bucket now caps login POSTs
  per IP, gated by its own `ICEBERG_EBS_LOGIN_RATE_LIMIT_ENABLED` switch (on in the Compose/Helm
  env) so disabling API limiting can't silently drop login protection.
- **Alerts no longer drop an older same-type event when several are pending** (#144). The
  recoverable-alert marker (#109) can hold two events of one type — e.g. a `new_version`
  1.0→1.1 whose webhook delivery failed and was retained, then a 1.1→1.2 the next cycle.
  `fire_alerts` collapsed the event list to one per type (dict last-wins), so only the newest
  was POSTed and logged; `fire_pending_alerts` then cleared the whole marker, losing the older
  transition with no `AlertLog` row. It now groups rules by event type and delivers **every**
  event (oldest→newest), so a consumer learns each transition — e.g. a risk level that went
  low→high→low — instead of just the final one.
- **Running the test suite no longer leaves the dev database unbootable** (#113). The suite
  builds its schema with `create_all` and drops it at teardown, but `alembic_version` isn't a
  SQLModel table so it survived — stamped at head over an empty schema. The next `make dev`
  trusted the stamp, ran no migrations, and crashed on startup (`relation "user" does not
  exist`). Two-part fix: the test fixture now drops `alembic_version` in both setup and
  teardown (leaving a clean, bootable DB), and `init_db`'s migration runner now self-heals a
  stamped-but-empty database by resetting to base and rebuilding from scratch — so the app
  recovers regardless of how the stale stamp arose. The self-heal is inert in production, which
  never drops tables. CI and production were never affected (CI gets a fresh container per run).
- The dashboard no longer returns a raw JSON **422 on a non-numeric `page`** query param
  (e.g. a mangled or hand-edited `?page=abc`) — like the other filter params it now tolerates
  junk and falls back to page 1 instead of rejecting the browser navigation (#152).
- **Input validation for identity-like fields** (#154): `POST /api/users` now rejects a blank /
  whitespace-only or multi-KB `username` (422) and strips surrounding whitespace, and stores a
  blank `email` as `NULL`; and `POST /api/inventory` rejects a blank `asset_id` **per row**
  (reported `invalid`, not failing the batch) and strips it — previously an empty `asset_id`
  upserted a real `InstallObservation` and counted as a distinct asset, inflating
  `install_footprint` and therefore the exposure / Top-exposure ranking.
- **Retention pruning now runs at startup**, then daily — previously the job's first fire was
  scheduled at process-start + 24h, so a deployment that restarts more often than daily
  (crash / OOM / redeploy) would **never** prune despite `ICEBERG_EBS_RETENTION_DAYS` being set,
  and `FetchLog` / `InstallCountHistory` / `AlertLog` grew unboundedly. The interval job now
  carries `next_run_time=now`; it fires on the scheduler executor after startup, so it doesn't
  delay the server binding (#145).
- A store becoming unreachable during an **interactive** add or refresh
  (`POST /api/extensions`, `…/{id}/refresh`) no longer surfaces a raw 500 with no record: a
  raw `httpx.TransportError` (retries exhausted — connect refused / timeout) is now handled
  like the scheduler already does, returning **502** and writing a `success=False` `FetchLog`
  so the dashboard's per-extension status and Fetch-health tile see the failure. The two paths
  previously disagreed on what a store outage looked like (#148).
- The extension detail page and JSON API no longer 500 when a stored JSON column
  (`permissions`, `risk_detail`, `package_analysis`) holds **valid JSON of the wrong shape** —
  e.g. an array where an object is expected, from a partial write or manual DB edit. Reads now go
  through typed `Extension` accessors (`permissions_list()` / `analysis_dict()` / `risk_detail_dict()`
  / `pending_events()`) that own one defensive parse guarding both unparsable *and* wrong-shape JSON,
  extending the earlier #17/#61 hardening that only covered unparsable JSON (#167).
- The single-extension JSON API no longer 500s on a **malformed `findings` list** in
  `package_analysis` — a non-dict entry, a finding dict missing required fields, or a `findings`
  value that isn't a list. Findings now deserialize tolerantly (non-dicts skipped, missing string
  fields defaulted) the way the detail page already did, completing the #167 wrong-shape hardening
  for the last stored-JSON read path (#150).
- Startup no longer blocks on re-delivering recovered webhook alerts: `recover_pending_alerts` no
  longer runs during lifespan startup at all — it's deferred to the head of each scheduler refresh
  cycle (where it already ran), backed by the durable pending-alert marker. Previously a backlog of
  undelivered alerts behind a dead/slow destination could burn one webhook timeout per pending
  extension before `/healthz` answered — long enough to trip the liveness probe and get the pod
  killed mid-recovery. Recovered alerts are now re-fired on the next cycle (≤ `fetch_interval_minutes`
  later) instead of at startup; nothing is lost, and recovery runs in exactly one place so it can't
  race a concurrent refresh's delivery of the same events (#155).
- A transient Chrome scrape mis-parse (a 200 page with a shifted layout) no longer clobbers
  the stored publisher/install count/last-updated date, spiking the risk score ~+31 and firing
  spurious `risk_level_change` alerts — stored values are kept, matching the existing guards
  on `version` and `permissions`. The user-count/version scrapers also now only read visible
  page text, so a store description like "Join 1,000,000 users" can't hijack them (#142).
- Adopting a pre-Alembic database now stamps it at the **baseline** revision and upgrades to
  head, instead of stamping it at head — which silently marked every post-baseline migration
  as applied without running it, permanently (first watchlist refresh and inventory pushes
  would then fail against the missing columns/tables). Databases already corrupted by that
  false stamp are detected at startup (baseline-era schema behind a post-baseline revision)
  and repaired the same way (#143).
- Broad host patterns (`*://*/*`, `http://*/*`, `https://*/*`) now score as critical like
  `<all_urls>` — previously only the literal `<all_urls>` spelling affected the risk score,
  and MV2 manifests carrying `*://*/*` or `file:///*` in `permissions` were missed by the
  broad-host finding entirely (#141).
- `store_url` was never persisted — every enrolled extension had an empty store URL (#72).
- Infinite redirect loop between `/` and `/login` for a stale-but-signed session cookie (#73).
- Admin UI pages returned raw 401/403 JSON instead of redirecting to the login page (#7).
- The extension-detail page could 500 on malformed stored JSON (#17, #61).
- A failed first fetch left an orphaned placeholder extension row (#75).
- Check-then-insert races in enrollment and inventory upsert could surface as a 500 (#76).
- Package-download failures were swallowed by a broad `except Exception`, hiding real bugs and
  silently scoring extensions from a midpoint fallback (#10).
- Publisher-name matching produced scoring false positives (#18).
- Deleting a user destroyed alert history that should have been preserved (#28).
- `ICEBERG_EBS_RETENTION_DAYS` and `ICEBERG_EBS_FETCH_INTERVAL_MINUTES` were **silently ignored by
  the production deploy stacks** — the Compose `app` service didn't forward them and the Helm chart
  had no `retentionDays`, so an operator following the docs got no pruning. `RETENTION_DAYS` and
  `FETCH_INTERVAL_MINUTES` (plus `SESSION_MAX_AGE` and `HTTPX_TIMEOUT`, which README advertised but the
  stacks ignored) are now forwarded by Compose and the Helm ConfigMap, and DEPLOYMENT.md documents
  which env vars the stacks forward vs. which fall back to `app/config.py` defaults (#87).
- The Helm chart **defaulted `image.tag` to the mutable `latest`** with `pullPolicy: IfNotPresent`,
  so `helm upgrade` re-rendered an identical pod spec (no rollout) and nodes reused their cached
  image — deploys silently shipped stale code, and `helm rollback` couldn't restore a known-good
  build. `image.tag` now has **no default** and is `required` at render time, forcing an explicit
  immutable release tag (`--set image.tag=v0.1.0-beta.1`) (#88).
- **Alerts could be silently dropped on restart** — the scheduler shut down with `wait=False`,
  abandoning an in-flight refresh; a shutdown between committing a state change and firing its alert
  left the change persisted but the alert never sent (and never retried, since the next cycle sees no
  diff). Pending change events are now persisted in the **same commit** as the state change
  (`Extension.pending_alert_events`) and **merged** across refreshes (never overwritten), so a restart
  re-fires anything undelivered; delivery clears the marker with **compare-and-clear**. Both are
  **atomic against a concurrent refresh of the same extension** (a manual API refresh racing the
  scheduler): the merge re-reads the marker under a `SELECT … FOR UPDATE` row lock before appending,
  and the clear is a single conditional `UPDATE … WHERE pending_alert_events = <delivered>` — so
  neither a lost-update nor a TOCTOU clear can drop an alert. Shutdown now **explicitly drains the
  in-flight refresh** (pause
  + await, bounded by `ICEBERG_EBS_SHUTDOWN_DRAIN_SECONDS`) — APScheduler 3.x's `shutdown(wait=True)`
  cancels rather than awaits async jobs, so it alone doesn't drain. The container grace period
  (`terminationGracePeriodSeconds` / `stop_grace_period`) is raised above that window, and the HTTP
  client is closed on shutdown (#109).
- **Documentation reconciled with the as-built system.** The in-app help page now documents
  API keys / bearer-token auth, corrects the Chrome/Edge extension-ID format (32 characters
  a–p, not "alphanumeric"/"GUID-like"), and no longer claims user deletion removes the user's
  extensions (they are kept, unassigned and off the watchlist). README/CONTRIBUTING/CLAUDE.md
  now describe all **six** CI gates (the `lint-workflows` and `ui` jobs were missing) and the
  four-service Compose stack; DEPLOYMENT.md's embedded Dockerfile/compose/nginx/Helm snapshots
  match the shipped hardened stack (backup service, read-only rootfs, `nginx:1.29-alpine`,
  `object-src 'none'`, NetworkPolicy/PDB templates, `readOnlyRootFilesystem` no longer
  "optional") and its env-var reference includes `ICEBERG_EBS_LOG_JSON` + the retry/circuit
  tuning knobs; SECURITY.md mentions the #107 Origin/Referer CSRF middleware; TODO.md/PLAN.md
  no longer list shipped features (filtering, bulk import, export, retention, inventory) as
  open work.

### Security

- **Database backups are no longer baked into the app image** (#277). `.dockerignore` excluded
  `.env`, `tests/`, and `caddy/certs/` but not `backups/` — the directory the Compose `backup`
  service fills with `pg_dump -Fc` archives of the live database. Since the Dockerfile does
  `COPY . .` and `.gitignore` has no bearing on the Docker build context, the documented
  `docker compose up --build` upgrade path copied every dump — user rows with bcrypt hashes,
  watchlist data, alert destinations and their webhook URLs — into the image layers, readable by
  anyone who can pull the image and shipped wholesale if it is ever pushed. It also grew the build
  context without bound as backups accumulated. `tests/test_backup.py` now derives the host
  directory from the Compose mount and asserts it is excluded, so a rename can't reopen the hole.
- **SSO: RP-initiated logout + shorter SSO session lifetime** (#221). Logging out of an SSO account
  now redirects to the IdP's `end_session_endpoint` (with the `id_token_hint`) so the provider
  session is terminated, not just the local cookie — falling back to a local-only logout when the
  provider has no such endpoint. SSO sessions also expire on a shorter, configurable lifetime
  (`ICEBERG_EBS_OIDC_SESSION_MAX_AGE`, default 1h) than local password sessions: an IdP-side
  disable/reset can't be pushed to us, so a short lifetime forces re-authentication through the IdP
  — which fails for a disabled account — bounding how long a stale session or stolen cookie survives.
  Continuous back-channel logout and an explicit IdP block/allowlist remain tracked follow-ups.
- **SSO: closed a cross-provider identity-spoofing hole** (#226). OIDC provisioning matched an
  account on the validated `(oidc_issuer, oidc_subject)` pair *globally*, but Authlib only checks a
  token's `iss` against the *originating* provider's own discovery metadata — so a hostile or
  compromised configured provider could publish another provider's issuer, serve its own JWKS, and
  mint a token carrying that trust domain's `(iss, sub)` to log in as (or pre-squat) the other
  provider's account, including admin sync. The provisioning match is now scoped to the configured
  provider (`auth_provider`); the same `(issuer, subject)` presented under a different provider is
  refused as an `"identity conflict"` (the global `uq_user_issuer_subject` constraint is the DB
  backstop). The issuer stays in the key, so a re-pointed adapter still can't inherit an account
  (#218). Regression test covers a second provider declaring the first's issuer with a distinct email.
- **CSV export is hardened against spreadsheet formula injection** — a tracked extension's
  attacker-controlled `name`/`publisher` (e.g. `=HYPERLINK(...)`, `+SUM(...)`, `@cmd|…`) is no
  longer written verbatim into the CSV. Cells starting with a formula-trigger character
  (`= + - @` tab/CR) are prefixed with a single quote so Excel/LibreOffice treat them as text,
  not live formulas, when an analyst opens the export (OWASP mitigation). The JSON export is
  left as raw values (not opened as a spreadsheet) (#147).
- **Session and API-key revocation on password change** — changing a password invalidates
  other-device sessions and deletes the user's API keys (#6).
- **Application-level login rate limiting and lockout**, independent of nginx (#8).
- The login rate limiter's client-IP key was **spoofable via `X-Forwarded-For`**; the reverse
  proxy now overwrites rather than appends it (#77).
- **Webhook SSRF defence** — destination URLs are validated at create/update time *and again at
  send time*, the request is pinned to the validated IP (preserving `Host` and TLS SNI), and
  redirects are disabled.
- The webhook-test endpoint **leaked internal error strings** (resolved IPs, internal hostnames)
  to the caller (#9).
- **Host-permission changes** (e.g. gaining `<all_urls>`) were excluded from `permission_change`
  alerts — a compromised update could widen host access silently (#60).
- Credential verification always pays the bcrypt cost, so an unknown username cannot be
  distinguished by timing; the dummy hash can no longer drift from the real cost factor (#14).
- CSRF protection is a **documented, deliberate** decision — `SameSite=Lax` + `Secure`, a
  JSON-only API, and bearer tokens as the primary M2M credential, rather than tokens (#16).
- Added `LICENSE` (Apache-2.0), `SECURITY.md` (private reporting + an explicit scope of what is
  and is not a trust boundary), `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md` (#92).
- **GitHub Actions are SHA-pinned** (with the release tag in a trailing comment) and checkout
  credential persistence is disabled, so a repointed action tag cannot run arbitrary code in CI —
  including the GHCR-pushing build job — and the repo token is no longer left in the workspace
  `.git/config` (OWASP CICD-SEC-3/4) (#96).
- **A blocking `lint-workflows` CI job** audits the workflows on every PR with **zizmor** (CI/CD
  security: unpinned actions, credential persistence, template injection, over-broad permissions)
  and **actionlint** (syntax + shellcheck), so the pinning/least-privilege posture above cannot
  silently regress (#97).
- **Auth hardening (#67)** — `ICEBERG_EBS_SECRET_KEY` shorter than 32 characters is now rejected at
  startup (a weak key undermines all itsdangerous cookie/flash signing), and passwords longer than
  bcrypt's 72-byte limit are rejected explicitly (a clean `422`) instead of being silently
  truncated — truncation previously let two distinct passwords sharing a 72-byte prefix collide.
- **CodeQL SAST** (`codeql.yml`) now runs dataflow/taint analysis over both **Python** and
  **JavaScript/TypeScript** on every PR, on push to `main`, and on a weekly schedule (to catch new
  advisories against already-merged code). It is a dedicated workflow so its `security-events: write`
  scope stays out of the least-privilege CI gates (#98).
- **App-layer security-header floor (#66)** — the app now emits a conservative HSTS (over HTTPS
  deployments) and a minimal CSP (`frame-ancestors`/`base-uri`/`object-src`/`form-action`) as
  defence-in-depth, so a floor is present even if the reverse-proxy header config regresses. nginx
  now strips the upstream copies and re-adds its **canonical** CSP + HSTS, so exactly one value
  reaches the client in production (no duplicate/first-wins `Strict-Transport-Security`); the app
  CSP omits `script-src`/`default-src` so it can never intersect with and break the proxy's policy.
- **Signed, attested release pipeline** (`release.yml`) — pushing a `v*` SemVer tag verifies the tag
  matches `pyproject.toml` **and that the tagged commit is on `main`** (so a release can only come
  from reviewed, merged history), then builds a release image with an **SBOM** and **SLSA build provenance**,
  **attests** the provenance to GHCR, **signs it keylessly with cosign**, and cuts the GitHub Release.
  Release images are immutable and digest-pinnable, so a consumer can verify what is in the image and
  that this repo's CI built it. `build.yml` no longer publishes a mutable `:latest` — main pushes are
  dev-only `:<sha>` + `:edge`; deployables come only from a tagged release (#99).
- **CSRF origin-check middleware (#107)** — a `CSRFOriginMiddleware` now rejects
  cookie-authenticated, state-changing requests (POST/PUT/PATCH/DELETE) whose `Origin`/`Referer`
  doesn't match the request host (or `ICEBERG_EBS_TRUSTED_ORIGINS`), as defence-in-depth over the
  existing `SameSite=Lax` posture (#16). Bearer-token (M2M) requests carry no session cookie and are
  never checked, so the API's primary credential is unaffected.
- **Hardened the Docker Compose stack (#102)** — the `app` and `nginx` services now run with
  `no-new-privileges`, `cap_drop: [ALL]` (nginx adds back only `NET_BIND_SERVICE` + the master's
  user-drop caps), a **read-only root filesystem** with tmpfs for the few writable paths, and
  healthchecks (app → `/readyz`, nginx → a plain-HTTP `/nginx-health`); `postgres` gets
  `no-new-privileges` (keeping the caps its entrypoint needs). nginx now waits for the app to be
  `service_healthy` before starting.
- **Completed the Helm pod-security baseline (#104)** — the deployment adds
  `seccompProfile: RuntimeDefault` and `automountServiceAccountToken: false` (the app never calls the
  Kubernetes API), a `strategy: Recreate` rollout so a deploy never briefly runs two scheduler pods
  (a rolling update with `replicas=1` would surge to two), and a `PodDisruptionBudget`
  (`maxUnavailable: 0`, toggleable) so a voluntary eviction can't take the singleton to zero.
  `runAsNonRoot`/`readOnlyRootFilesystem`/`cap_drop: [ALL]`/`allowPrivilegeEscalation:
  false` were already in place — the chart now meets Pod Security Standards *restricted*.
- **Kubernetes NetworkPolicies (#103)** — the Helm chart adds default-deny ingress plus named hops
  (ingress-controller → app:8000, app → postgres:5432), turning the previously flat namespace into
  a segmented one so a single compromised pod can't reach Postgres directly. Egress is left open
  (the app must reach the extension stores, webhooks, and TI feeds). The Bitnami postgresql
  subchart's own (default-permissive) NetworkPolicy is disabled so it can't union back broader
  ingress to Postgres. Gated behind `networkPolicy.enabled` (default on); requires a CNI that
  enforces NetworkPolicy (Calico/Cilium).

[0.1.0-beta.1]: https://github.com/IcebergAI/IcebergEBS/commits/main
