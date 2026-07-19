---
title: Alerts & API
icon: material/webhook
---

<p class="eyebrow">Integration</p>

# Alerts & API

IcebergEBS is API-first: the UI consumes the same REST endpoints you can drive from
a SOAR playbook, and change detection pushes out over webhooks.

## What raises an alert

Four event types, raised by comparing each fetch against the previous state:

| Event | Fires when |
|---|---|
| `risk_level_change` | The risk **band** changed — see [risk bands](scoring.md#risk-bands) |
| `publisher_change` | The publisher name changed |
| `permission_change` | The permission set changed, including host permissions |
| `new_version` | A new version was published |

Two details worth internalising:

- **Bands, not scores.** A score moving 51 → 62 is not an event; 49 → 51 is. This
  keeps normal metadata drift out of your inbox while a genuine escalation still
  pages.
- **The first fetch is silent.** A newly added extension has no prior state, so it
  raises nothing — adding a hundred extensions does not produce a hundred alerts.

`permission_change` diffs API permissions *and* host permissions from the inspected
package, so an extension quietly gaining `<all_urls>` in an update alerts even
though its declared permission list may look similar.

## Destinations and rules

A **destination** is a webhook URL with a label and an enabled flag. A **rule**
binds one event type to one destination, optionally narrowed to a single extension —
leave the extension unset and the rule covers everything you track.

!!! note "Webhooks are the transport"
    Webhook POST is the only delivery mechanism. Slack, Teams, PagerDuty, and
    similar are reachable as incoming-webhook URLs; there is no built-in email or
    SMS transport.

Delivery is logged whether it succeeds or fails — a failed POST records the error
rather than raising, so one dead destination cannot stall a refresh cycle. You can
read that history back from the API, and send a test payload to any destination.

### Payload

The test payload and the real thing are built by the same code, so what you see when
testing is what you will receive:

```json
{
  "text": "Human-readable summary",
  "event": "new_version",
  "extension": {
    "id": 1,
    "name": "Example Extension",
    "store": "chrome",
    "store_url": "https://chromewebstore.google.com/detail/…",
    "iceberg_ebs_url": "https://icebergebs.example.com/extensions/1"
  },
  "change": { "old": "1.4.2", "new": "1.5.0" },
  "risk_score": 62
}
```

`iceberg_ebs_url` is only present when `ICEBERG_EBS_APP_BASE_URL` is configured —
set it, so an alert in a chat channel links straight back to the detail page.

### Delivery guarantees

Detected events are persisted **in the same transaction** as the state change that
produced them, and the marker is only cleared once delivery has been attempted. If
the process dies between the two, the next scheduler cycle re-fires the survivors.
The trade is deliberate: an alert may be **delivered twice**, but it is not lost.
Treat your receiver as idempotent.

## REST API

Everything lives under `/api`. Authenticate with a **Bearer token** (an API key) or,
for the browser UI, the session cookie. API routes always return `401` rather than
redirecting to the login page.

| Group | Endpoints |
|---|---|
| **Extensions** | `GET /api/extensions` (paginated, filter by store/risk/publisher/query), `POST /api/extensions`, `POST /api/extensions/bulk`, `POST /api/inventory`, `GET /api/extensions/export?format=csv\|json` |
| **One extension** | `GET`, `DELETE`, `POST …/refresh`, `PATCH …/watchlist`, `GET …/history` under `/api/extensions/{id}` |
| **Alerts** | `/api/alerts/destinations`, `/api/alerts/rules` (both full CRUD), `POST /api/alerts/destinations/{id}/test`, `GET /api/alerts/log` |
| **API keys** | `GET`, `POST`, `DELETE` under `/api/keys` |
| **Users** *(admin)* | `/api/users`, plus self-service `PATCH /api/users/me/password` |
| **Admin config** | `/api/proxy/settings`, `/api/proxy/test`, `/api/oidc/settings` |

Bulk endpoints are capped — 100 for `POST /api/extensions/bulk`, 1000 for
`POST /api/inventory`, which is the endpoint to point an inventory export at.

### API keys

Create a key from **Account → API keys** or `POST /api/keys`. The raw key is
returned **exactly once**, at creation; only a hash is stored, plus a short prefix
and suffix so you can recognise it later. Keys can be created **read-only**, in
which case any non-`GET` request is rejected — use that for a dashboard or a SIEM
poller.

Changing your password **deletes all of your API keys** and invalidates sessions on
other devices. That is the revocation path for a leaked token.

### Ownership

Every user maintains an independent watchlist. List queries are filtered to the
calling user, and requesting another user's object returns **404**, not 403, so
object IDs cannot be probed. Admin is a *user-management* role — it does not grant
access to other users' extensions or alerts.

### Interactive docs

Swagger UI is at `/docs`, ReDoc at `/redoc`, and the schema at `/openapi.json`.

!!! info "The docs routes need a session cookie"
    Unlike the API itself, the schema and documentation routes authenticate via the
    **browser session** — a Bearer-only client cannot fetch `/openapi.json`. Open
    them in a logged-in browser.

[:octicons-arrow-right-24: How the scores those alerts fire on are computed](scoring.md)
