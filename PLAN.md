# IcebergEBS — Roadmap to "SOC-consumable" (product, not infra)

> This document supersedes the original from-scratch build plan. The app is built; this is the
> forward-looking roadmap to make IcebergEBS consumable by a mid-size SOC.

## Context

IcebergEBS today is a solid **single-team extension risk scanner**: multi-store fetchers (Chrome/Edge/
VS Code), a genuinely capable static inspector ([app/inspector.py](app/inspector.py) — permissions,
eval/remote-code, CSP, network callouts, obfuscation, MV2, severity-tagged findings with file:line),
heuristic 0–100 scoring ([app/scoring.py](app/scoring.py)), webhook alerting with SSRF protection +
change detection ([app/notifications.py](app/notifications.py)), API keys + session auth, a background
scheduler, and a ~390-test suite.

To be **consumed by a mid-size SOC**, it needs to become an *extension attack-surface management*
product: tied to the org's real install footprint, integrated with SOC tooling, governed by enterprise
identity, and tuned to catch the attacks that actually matter (malicious **updates** to trusted
extensions, and **known-bad** extensions). This is a phased roadmap, not a single feature.

**Scope decisions:**
- **Consumption:** both an analyst UI *and* a first-class API/integration surface.
- **Fleet inventory:** ingested **from the SOAR via a IcebergEBS API** (bulk upsert) — IcebergEBS does **not**
  build direct Chrome Enterprise/Intune/EDR connectors. SOAR owns collection; IcebergEBS owns scoring +
  exposure.
- **Identity:** SSO (SAML/OIDC) + roles is a **hard rollout gate**.
- **Detection priorities:** (1) **update diffing**, (2) **malicious-extension feeds**. Automated
  VT/OTX enrichment and tunable scoring are explicitly *later*.

Reusable seams that most epics build on: `fetch_and_store`/`fire_pending_alerts`
([app/services.py](app/services.py)), `detect_changes`/`fire_alerts` ([app/notifications.py](app/notifications.py)),
`get_fetcher` ([app/fetchers/__init__.py](app/fetchers/__init__.py)), `compute_risk_score`/`risk_level`
([app/scoring.py](app/scoring.py)), `require_api_auth`/`require_admin` ([app/auth.py](app/auth.py)),
`build_threat_intel_indicators` ([app/threat_intel.py](app/threat_intel.py)), the `AlertDestination`/
`AlertRule`/`AlertLog` models + the Alembic migration setup ([alembic/](alembic/), wired up by
[app/database.py](app/database.py)).

---

## Phase 0 — Operability & quick wins ✅ SHIPPED

Make it survive a real watchlist and a real team. Mostly backend, low risk. **All Phase 0 items are
built:**

- ~~**Data retention / pruning**~~ — shipped (#22): daily prune job in [app/retention.py](app/retention.py),
  gated by `ICEBERG_EBS_RETENTION_DAYS`.
- ~~**Pagination + filter + search**~~ — shipped (#23): `GET /api/extensions` returns a paginated
  envelope with store/risk/publisher/free-text/sort filters, shared with the dashboard via
  `build_extension_query`.
- ~~**Bulk import**~~ — shipped (#24): `POST /api/extensions/bulk` + UI paste box.
- ~~**Export**~~ — shipped (#25): `GET /api/extensions/export?format=csv|json`.
- ~~**Fetch health**~~ — shipped (#26): per-extension last fetch status/error, fleet "Fetch health"
  tile, `/healthz` + `/readyz`; hardened further by the retry transport + per-store circuit breaker (#108).
- ~~**Postgres-by-default**~~ — shipped, and then some: SQLite support was **removed** entirely;
  Postgres is the only supported database (dev, test, prod), with schema managed by Alembic.
- ~~**Known-bug cleanup**~~ — shipped (#28): `delete_user` preserves history; `build_threat_intel_indicators`
  output is capped (`MAX_THREAT_INTEL_INDICATORS`).

## Phase 1 — SOC core value: inventory, update-diffing, malicious feeds

The headline differentiators. Backend-heavy; leverages the existing fetch/alert pipeline.

- ~~**SOAR-fed inventory + exposure (blast radius).**~~ **Shipped (#29):**
  - `InstallObservation` model (one row per extension × asset) + cached `install_footprint` on
    `Extension`.
  - `POST /api/inventory` — bulk upsert from SOAR; **auto-enrolls** unknown extensions (scoring
    deferred to the scheduler, #78), so pushing inventory expands the watchlist automatically.
  - **exposure = risk_score × footprint** is sortable everywhere; the dashboard has a "Top exposure"
    section and the detail page an "Org footprint" card (assets + per-department breakdown).
- **Update diffing (catch compromised/sold extensions).**
  - New model `PackageSnapshot(extension_ref, version, package_sha256, analysis_json, captured_at)` —
    today only the *latest* `package_analysis` is kept ([services.py](app/services.py#L113)). Store a
    snapshot per version.
  - `diff_analysis(old, new)` → added permissions / new remote-code / new callout domains / new
    findings. New alert event `capability_change` (a.k.a. "risky update") wired through the **existing**
    `detect_changes` → `fire_alerts` path; add it to `VALID_EVENT_TYPES`
    ([alerts.py](app/routes/api.py)) and `risk_level`/event docs. Surface the diff on the detail page.
- **Malicious-extension feeds.**
  - New model `ThreatListEntry(store, extension_id, source, reason, added_at)` + a loader (scheduled
    pull *and* `POST /api/threatlist` so SOAR can push). Matcher in the score path forces **critical** +
    a `threat_match` finding and fires a `threat_match` alert event. Reuses scoring override hook +
    notifications.

## Phase 2 — Identity & governance (rollout gate)

Required before a SOC will adopt. Can run in parallel with Phase 1.

- **SSO** — OIDC first (Authlib): `/auth/oidc/login` + callback, IdP group→role mapping; SAML second
  (python3-saml) for IdPs that require it. Keep local accounts as break-glass.
- **RBAC** — replace the `User.is_admin` bool with a `role` enum (`admin` / `analyst` / `auditor`);
  generalize `require_admin` → `require_role(...)` ([auth.py](app/auth.py#L128)). Auditor = read-only,
  analyst = triage but not user/destination admin.
- **Audit log** — new `AuditLog(actor, action, target_type, target_id, detail, at)` written on every
  mutating action (extension add/delete, rule/destination CRUD, risk-acceptance, user changes). This is
  the compliance/forensics trail a SOC needs and is currently absent.
- **MFA** for local break-glass accounts (TOTP) if SSO is unavailable.

## Phase 3 — Integrations & analyst workflow

Makes "both UI + API" real.

- **Stable, versioned API + OpenAPI for SOAR** — un-gate a scoped OpenAPI spec for API-key consumers
  ([main.py](app/main.py)); document the event schema; semantic-version the API.
- **Outbound integrations** — generalize `AlertDestination` with a `kind` (webhook today) to add
  **Slack/Teams/email** (SMTP) and **ticketing** (Jira/ServiceNow create-issue) destinations; reuse
  `send_webhook` for webhook kinds, add senders per kind ([notifications.py](app/notifications.py),
  [webhooks.py](app/webhooks.py)). (Email is also an author TODO.)
- **SIEM export** — emit alerts/findings as **OCSF** (or CEF/ECS) events to an HTTP collector
  (Splunk HEC / Sentinel / Elastic). **STIX 2.1** bundle export reusing
  `build_threat_intel_indicators`.
- **Triage workflow** — `triage_status` (new/triaging/accepted-risk/blocked/resolved) + assignee +
  notes on `Extension`; **allow-list/deny-list** that overrides the heuristic score (approved extensions
  suppressed; blocked ones forced critical). Ties allow/deny back into Phase 1's scoring override hook.

## Phase 4 — Reporting & secondary detection (later)

- **Posture reporting** — fleet risk over time, top exposure by blast radius, exposure by department,
  triage MTTR; **scheduled digest** webhook/email (author TODO); printable per-extension risk report.
- **Automated TI enrichment** — call VirusTotal/OTX with API keys, cache verdicts, fold into score
  (today [threat_intel.py](app/threat_intel.py) only deep-links).
- **Tunable scoring** — move `scoring.py` weights/thresholds into config/policy; per-org policy editor.
- **Coverage** — Firefox AMO fetcher (public REST API; author TODO); deeper MV3 analysis;
  CVE/advisory correlation.

---

## Cross-cutting concerns (apply every phase)
- **Migrations:** schema is managed by **Alembic** — add every new table/column via
  `alembic revision --autogenerate` (see CLAUDE.md's `app/database.py` notes); the old hand-rolled
  `_migrate_*` startup path is retired.
- **Alerts after commit:** any new write path that fires alerts must commit first, then
  `fire_pending_alerts` — `fire_alerts` opens its own second DB session, which must not run inside
  the caller's still-open write transaction (see CLAUDE.md).
- **Tests:** each epic ships unit + route tests in the existing style ([tests/](tests/), respx + the
  `client`/`test_db` fixtures); keep the suite green.
- **Docs:** update [CLAUDE.md](CLAUDE.md) module/architecture notes and [help.html](app/templates/help.html)
  per the Maintenance rule.

## Recommended sequencing
Phase 0 (≈1 sprint) → **Phase 1 + Phase 2 in parallel** (the value + the rollout gate) → Phase 3 →
Phase 4. SSO/RBAC/audit (Phase 2) gates go-live, so start it alongside Phase 1 rather than after.

---

## Verification (per phase, end-to-end)
- **Phase 0:** `pytest` green; seed >200 extensions, confirm paginated/filtered list + CSV export;
  run prune job and assert old `FetchLog`/`AlertLog` rows removed; `/healthz` returns ok.
- **Phase 1:** `POST /api/inventory` with a SOAR-style batch → unknown extension auto-enrolled + scored,
  footprint + exposure shown; bump a test extension's version with a new dangerous permission →
  `capability_change` alert fires and the diff renders; add an ID to the threat list → extension flips
  to critical + `threat_match` alert + AlertLog row.
- **Phase 2:** OIDC login maps IdP group → `analyst`; auditor blocked from mutating routes (403);
  every mutation writes an `AuditLog` row; verify in DB.
- **Phase 3:** OpenAPI reachable with an API key; a Slack + a Jira destination both deliver on a fired
  rule (AlertLog records both); OCSF event posted to a mock collector; allow-listed extension drops to
  suppressed, deny-listed forced critical.
- **Phase 4:** scheduled digest delivered; VT verdict cached and reflected in score; changing a policy
  weight changes the recomputed score; a Firefox AMO extension fetches + scores.
