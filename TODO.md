# TODO

## Features

### Alerting

- **Email alerts** — webhooks require a Slack/Discord endpoint or custom receiver. Email is the natural fallback for users without existing webhook infrastructure.
- **Scheduled digest** — a weekly summary webhook/email instead of per-event alerts; useful for extensions that change rarely and where noise is a concern.

### New data / analysis

- **Package diff across versions** — `package_analysis` is only stored for the latest fetch. Keeping a previous snapshot and diffing findings across a version bump would answer "what actually changed in this update."
- **Firefox AMO support** — Chrome, Edge, and VS Code are covered. AMO has a public REST API (`https://addons.mozilla.org/api/v5/`).

## Done (kept for reference)

- ~~Risk score history chart~~ — rendered on the extension detail page's History tab from `FetchLog` data.
- ~~Manual refresh button~~ — "Refresh now" on the extension detail page, wired to `POST /api/extensions/{id}/refresh`.
- ~~Bulk import~~ — `POST /api/extensions/bulk` + paste-box UI (#24).
- ~~Dashboard filtering / search~~ — server-side filter/search/sort/pagination on the dashboard and `GET /api/extensions` (#23).
- ~~Export~~ — `GET /api/extensions/export?format=csv|json` (#25).
- ~~`delete_user` inconsistency~~ — user deletion now preserves history like `delete_rule`/`delete_destination` (#28).
- ~~No cap on threat intel indicator count~~ — `build_threat_intel_indicators` output is capped at `MAX_THREAT_INTEL_INDICATORS` (#28).
