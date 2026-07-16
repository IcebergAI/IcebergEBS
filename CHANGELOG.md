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

### Changed

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

### Fixed

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
