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

### Changed

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

### Fixed

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

### Security

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
- **Signed, attested release pipeline** (`release.yml`) — pushing a `v*` SemVer tag verifies the tag
  matches `pyproject.toml` **and that the tagged commit is on `main`** (so a release can only come
  from reviewed, merged history), then builds a release image with an **SBOM** and **SLSA build provenance**,
  **attests** the provenance to GHCR, **signs it keylessly with cosign**, and cuts the GitHub Release.
  Release images are immutable and digest-pinnable, so a consumer can verify what is in the image and
  that this repo's CI built it. `build.yml` no longer publishes a mutable `:latest` — main pushes are
  dev-only `:<sha>` + `:edge`; deployables come only from a tagged release (#99).

[0.1.0-beta.1]: https://github.com/IcebergAI/IcebergEBS/commits/main
