# TODO

## Features

### Quick wins (data already exists)

- **Risk score history chart** — `FetchLog` records `risk_score_before` / `risk_score_after` on every fetch. Render a sparkline or simple chart on the extension detail page to show risk trend over time.
- **Manual refresh button** — no way to trigger a fetch outside the scheduler. Wire the existing `POST /api/extensions/{id}/refresh` endpoint to a button on the extension detail page.

### UX improvements

- **Bulk import** — add a way to paste a list of extension IDs or upload a CSV rather than adding one at a time. Reduces friction for new users with an existing set of extensions to monitor.
- **Dashboard filtering / search** — filter by store, risk level, or publisher as the watchlist grows.
- **Export** — download the watchlist + current risk scores as CSV or JSON for reporting or external tooling.

### Alerting

- **Email alerts** — webhooks require a Slack/Discord endpoint or custom receiver. Email is the natural fallback for users without existing webhook infrastructure.
- **Scheduled digest** — a weekly summary webhook/email instead of per-event alerts; useful for extensions that change rarely and where noise is a concern.

### New data / analysis

- **Package diff across versions** — `package_analysis` is only stored for the latest fetch. Keeping a previous snapshot and diffing findings across a version bump would answer "what actually changed in this update."
- **Firefox AMO support** — Chrome, Edge, and VS Code are covered. AMO has a public REST API (`https://addons.mozilla.org/api/v5/`).

## Known bugs / tech debt

- **`delete_user` inconsistency** — `app/routes/users.py` cascade-deletes `AlertLog` rows when a user is deleted, whereas `delete_rule` and `delete_destination` now nullify `rule_id`/`destination_id` instead. User deletion should follow the same preserve-history pattern.
- **`_domain_from_url` duplication** — identical helper exists in both `app/inspector.py` and `app/threat_intel.py`. Extract to a shared utility.
- **No cap on threat intel indicator count** — `build_threat_intel_indicators` can emit ~1500 indicator dicts in the worst case (500 external URLs + 500 network callout URLs + domains). The individual lists are capped but the indicator builder iterates all of them uncapped.
- **`_migrate()` not exercised in tests** — `conftest.py` uses `create_all` directly; the incremental migration paths in `database._migrate()` have no test coverage.
