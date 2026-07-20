# Issue #37 — Outbound integrations: Slack/Teams/email + Jira/ServiceNow

Resolution plan. Generalize `AlertDestination` with a `kind` (webhook today) so alerts can
also deliver to **Slack**, **Teams**, **email (SMTP)** and **ticketing (Jira / ServiceNow
create-issue)** destinations, with a per-kind configuration UI.

**Acceptance (from the issue):** a Slack + a Jira destination both deliver on a fired rule;
`AlertLog` records both.

**Design principle (requested):** modular, mirroring the identity-provider abstraction —
`app/oidc/` (#32) defines a pure `base.py` with a Protocol + self-registering adapter
registry, one small module per provider, config validation in one place, and a thin
routes/UI layer. The alert-delivery side gets the same shape: an **`AlertSender` adapter
per destination kind** in a new `app/senders/` package.

---

## 1. Architecture — `app/senders/` adapter package

Mirrors `app/oidc/` module-for-module:

| OIDC (#32) | Senders (#37) | Role |
|---|---|---|
| `oidc/base.py` | `senders/base.py` | pure Protocol + registry + shared dataclasses (mypy-clean) |
| `StandardOIDCAdapter` (shared by authentik/auth0/okta) | `HttpJsonSender` (shared by webhook/slack/teams; extended by jira/servicenow) | one shared core, thin per-kind specializations |
| `oidc/entra.py`, `okta.py`, … | `senders/webhook.py`, `slack.py`, `teams.py`, `email.py`, `jira.py`, `servicenow.py` | one adapter per kind, self-registering at import |
| `oidc/config.py` `validate_config()` | per-adapter `validate(...)` | create/update-time validation → 422 |
| `oidc/__init__.py` | `senders/__init__.py` | imports adapter modules so registration runs |

**Webhook is not privileged.** Generic webhook is just one registered kind among six,
with the same standing as the others — nothing in the registry, `fire_alerts` dispatch,
API, or UI special-cases it. Structurally it's the inverse: Slack and Teams are
*specialised webhooks* (same POST-a-JSON-payload-to-a-user-supplied-URL delivery, a
different payload shape), so the three share one HTTP core and differ only in
rendering — exactly as authentik/auth0/okta are three registrations of
`StandardOIDCAdapter`. The only residual asymmetries are backwards-compatibility, not
design: the migration's `server_default='webhook'` (existing rows) and `DestinationIn.kind`
defaulting to `"webhook"` (existing API callers).

### `senders/base.py` (pure, typed — add to the mypy-enforced set)

```python
@dataclass(frozen=True)
class AlertMessage:
    """Normalised alert content every sender renders from."""
    text: str            # from notifications._alert_text
    event: str           # event_type ("test" for destination tests)
    ext_id: int | None
    name: str
    store: str
    store_url: str
    old: Any
    new: Any
    risk_score: int | None
    app_url: str | None  # settings.app_base_url deep link, when configured

class SenderError(Exception):
    """Delivery failure with a caller-safe message (no secrets, no resolved IPs)."""

class DestinationConfigError(Exception):
    """Invalid destination target/config; message is static + user-facing
    (same contract as WebhookValidationError)."""

@dataclass(frozen=True)
class ConfigField:
    name: str; label: str; required: bool = True
    placeholder: str = ""; help: str = ""

class AlertSender(Protocol):
    kind: str            # "webhook" | "slack" | "teams" | "email" | "jira" | "servicenow"
    label: str           # UI display name
    target_label: str    # what `target` means for this kind ("Webhook URL", "Recipients", …)
    config_fields: tuple[ConfigField, ...]   # drives the dynamic UI form

    async def validate(self, target: str, config: dict[str, str]) -> None: ...
    async def send(self, client: httpx.AsyncClient, target: str,
                   config: dict[str, str], message: AlertMessage) -> None: ...

# register_sender() / get_sender(kind) / all_senders() — same registry shape as oidc/base.py
```

Everything generic (SSRF validation, IP pinning, proxy routing, AlertLog bookkeeping,
retry semantics) stays outside the adapters — an adapter only knows its wire format,
exactly as an OIDC adapter only knows its claim mapping.

### The shared HTTP core + six peer adapters

**`HttpJsonSender`** (in `base.py`, or a sibling `http.py` if it grows) is the shared
delivery core for every HTTP-based kind — the `StandardOIDCAdapter` of this package.
It owns "POST a JSON body to the destination URL through the pinned-request machinery
(§ Delivery plumbing)" and exposes two hooks: `render_payload(message) -> dict` and
`request_headers(config) -> dict` (default: none). A specialization is therefore just
a payload renderer plus its `ConfigField` declarations.

Five of the six kinds are that shape; email is the one genuinely different transport:

- **`webhook.py`** — `HttpJsonSender` whose renderer is today's
  `build_alert_payload(...)` shape, verbatim. Existing rows become `kind="webhook"`
  and nothing changes on the wire.
- **`slack.py`** — `HttpJsonSender` rendering the Slack incoming-webhook shape
  (`{"text": ...}` + a Block Kit section with name/store/risk/old→new and the deep
  link). Works for Slack-compatible endpoints (Mattermost/Rocket.Chat) for free.
- **`teams.py`** — `HttpJsonSender` rendering an Adaptive Card for a Teams Workflows
  incoming-webhook URL
  (`{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", ...}]}`).
- **`jira.py`** — `HttpJsonSender` + auth headers: Jira Cloud `POST /rest/api/3/issue`.
  Target = site base URL (the adapter derives the API path); config = `project_key`,
  `issue_type` (default "Task"), `account_email`, `secret_ref` (§4). Basic auth
  `email:api_token` via `request_headers`. Summary = `message.text`; description
  carries the store/risk/old→new detail + deep link (ADF paragraphs).
- **`servicenow.py`** — `HttpJsonSender` + auth headers: `POST /api/now/table/{table}`
  (default `incident`). Target = instance base URL; config = `table`, `username`,
  `secret_ref`. `short_description` = `message.text`, `description` = detail block.
- **`email.py`** — the non-HTTP transport. Target = comma-separated recipient list
  (validated with stdlib `email.utils.parseaddr` — no new dependency); optional
  `subject_prefix` in config. Server settings are deployment-level env config (§4).
  Uses stdlib `smtplib` + `email.message.EmailMessage` offloaded via
  `anyio.to_thread.run_sync` — the same offload pattern as bcrypt in `auth.py`; no
  new runtime dependency (aiosmtplib not needed for one short-lived send per alert).

### Delivery plumbing changes

- **`app/webhooks.py`** grows a generalized `send_pinned_request(client, url, *, json,
  headers=None, timeout=...)` — the existing validate→resolve→pin→POST core with an
  optional caller-header merge (pinned `Host` always wins; `Authorization` is what
  Jira/ServiceNow add). `send_webhook` becomes a thin wrapper so existing call sites
  and tests are untouched. All five HTTP kinds go through it, so every kind inherits:
  SSRF validation **at create/update time and again at send time**, DNS-rebinding IP
  pinning, `follow_redirects=False`, proxy routing via the shared client's
  `ProxyRoutingTransport`, and the deliberate no-retry-on-POST rule.
- **`app/notifications.py:fire_alerts()`** — the only behavioural edit: build an
  `AlertMessage` once per (event, extension), then
  `await get_sender(dest.kind).send(client, dest.target, dest.config_dict(), msg)`
  instead of calling `send_webhook` directly. Everything else (rule matching,
  every-event delivery #144, `proxy.scrub`'d error capture, per-destination `AlertLog`
  row, own-session commit-after-caller-commit ordering) is untouched — which is what
  makes the acceptance criterion fall out for free: one fired rule with a Slack and a
  Jira destination produces two `send()` calls and two `AlertLog` rows through the
  existing loop.
- **Secret hygiene:** adapters must raise `SenderError` with safe static text (plus
  HTTP status where relevant) rather than leaking exception internals; `fire_alerts`
  keeps scrubbing + truncating as today (#228). SMTP delivery is plain TCP, not HTTP —
  it does **not** traverse the outbound proxy; that's documented (§6). Its host comes
  from env-only settings, and recipients are just addresses, so there's no
  user-controlled SSRF surface on that path.

## 2. Model + migration

`AlertDestination` gains two columns; `target` keeps its role as "the address":

```python
kind: str = Field(default="webhook")   # NOT NULL, server_default 'webhook'
config: str = "{}"                     # JSON-in-str, kind-specific non-secret extras
```

- New typed accessor `AlertDestination.config_dict()` via `utils.json_object` — the
  house rule (#167): consumers never `json.loads` the column directly.
- Alembic migration `alertdestination_kind`: add both columns with server defaults
  (existing rows become valid webhook destinations with no backfill), plus a **CHECK
  constraint** `kind IN ('webhook','slack','teams','email','jira','servicenow')` —
  same DB-level-invariant discipline as `39d4509e2a67_proxysettings_mode_check`
  (#217/#218 lesson: enforce invariants in the schema, not only app code).
- Downgrade drops the columns/constraint only — never user rows. Verify
  **up→down→up on a scratch DB** (via `docker exec <postgres> psql`; no host `psql`).
- `tests/test_migrations.py::test_head_matches_models` keeps model/migration in sync.

No `AlertRule`/`AlertLog` schema change: rules point at destinations by id regardless
of kind, and the log's `destination_id`/`success`/`error` columns already record
per-kind outcomes.

## 3. API (`app/routes/alerts.py`)

- `DestinationIn`/`DestinationOut`/`DestinationPatch` gain `kind: str = "webhook"` and
  `config: dict[str, str] = {}` (`Out` returns the parsed dict; nothing in `config` is
  secret — see §4 — so no redaction needed).
- Create/patch validation dispatches to the adapter:
  unknown `kind` → 422 listing valid kinds; `DestinationConfigError` → 422 with its
  static message (replacing the webhook-only `_validate_webhook_url` special case,
  which moves into `senders/webhook.py`).
- **Patch validates the resulting state**, not the changed fields (the #217/#216
  lesson — e.g. changing `kind` alone must revalidate the existing `target`+`config`
  under the new adapter).
- `GET /api/alerts/destination-kinds` → the registry's descriptors
  (`kind`, `label`, `target_label`, `config_fields`, `available`) so both the UI form
  and API/SOAR consumers discover kinds dynamically. `available=false` (with a reason)
  for `email` when SMTP is unconfigured — creation of an email destination is refused
  with the same static message.
- `POST /alerts/destinations/{id}/test` goes through `sender.send()` with a canned
  `AlertMessage(event="test", ...)` — preserving the "test is the real path by
  construction" property (#168) for every kind. Yes, testing a Jira/ServiceNow
  destination **creates one real test ticket**: that is the point — it proves project
  key, issue type, auth and field mapping end-to-end, where a mere auth ping would
  pass and then fail at 2am on a real alert. Documented on the help page.

## 4. Secrets & settings — env-only, like OIDC/proxy (#216/#32)

House rule: secrets never touch DB/API/UI/logs.

- **SMTP (deployment-level, one server):** new `Settings` fields
  `smtp_host`, `smtp_port=587`, `smtp_starttls=True`, `smtp_username=""`,
  `smtp_password: SecretStr = SecretStr("")`, `smtp_from` —
  `ICEBERG_EBS_SMTP_*`, exactly like the proxy credential block.
- **Per-destination API credentials (Jira/ServiceNow):** the destination row stores a
  **`secret_ref`** — an uppercase name, not a secret — resolved at send time from
  `ICEBERG_EBS_DEST_SECRET_<REF>` in the environment. `validate()` checks the ref
  resolves at create/update time (fail fast, static message), and `send()` re-reads it
  per delivery so a rotated env value applies on restart without touching the row.
  This keeps multiple Jira sites possible while honouring env-only secrets; the ref
  itself is safe to return from the API and render in the UI.
- Docs: `.env.example` + `DEPLOYMENT.md` (Compose: optional vars pass through as
  `${VAR:-}`/`env_file` — they must **not** join the `${VAR:?}` required set guarded by
  `tests/test_compose_secrets.py`; Helm: `extraEnv`/existing Secret).

## 5. Configuration UI (`account.html` + `static/js/pages/account.js`)

Extends the existing Alpine destinations panel, within the house constraints
(`@alpinejs/csp` build, no inline JS, `Alpine.data` registry + JSON-island pattern —
`.claude/rules/frontend.md`):

- The `#account-data` JSON island additionally carries the §3 kind descriptors.
- **New-destination form:** a kind `<select>`; the target input's label/placeholder and
  the extra config inputs render from the selected descriptor's `config_fields` via
  `x-for` — adding a future kind is adapter-only, zero template edits (the same
  "adapter declares, shell renders" split as the OIDC admin page).
- **List rows:** kind badge (styled in `app.css` with existing token patterns), label,
  per-kind target summary, and the existing enable/test/delete controls; the test
  button already renders per-row status and works unchanged for all kinds.
- Edit keeps parity with the API (kind change re-renders the config sub-form and
  revalidates server-side).
- Alert-log table gains nothing — destination label already identifies the channel.
- `help.html` updated (CLAUDE.md maintenance rule): kinds, SMTP/env setup,
  ticketing-test-creates-a-ticket note.

## 6. Testing

- **`tests/test_senders.py`** (new): registry completeness; per-adapter `validate()`
  accept/reject tables (bad URLs, bad recipients, missing project key, unresolvable
  `secret_ref`, SMTP-unconfigured email refusal); per-adapter payload-shape assertions
  with `respx` (Slack text, Teams Adaptive Card envelope, Jira ADF + basic auth header,
  ServiceNow table path); email via monkeypatched `smtplib.SMTP`; `SenderError`
  messages contain no secret material.
- **`tests/test_alerts.py`** additions: create/patch/list destinations per kind through
  the API (422 paths, kind-change revalidation, descriptors endpoint, `config`
  round-trip); test-endpoint per kind.
- **Acceptance test (the issue's criterion):** one extension change event, a rule per
  a Slack and a Jira destination → `fire_alerts` delivers both (respx) and writes two
  `AlertLog` rows (one per destination) with `success=True`.
- **Regression safety:** existing webhook tests must pass unmodified (webhook kind is
  behaviour-preserving); pending-marker recovery (#109/#144/#197) is untouched since
  `fire_alerts` remains the single delivery seam.
- **e2e (`ui` CI job):** extend the account-page smoke to open the new-destination
  form and switch kinds — this is the gate that catches an `@alpinejs/csp`-illegal
  expression at runtime.
- Migration up→down→up on a scratch DB (§2).

## 7. Documentation & bookkeeping

`CHANGELOG.md` entry; `.claude/rules/architecture.md` gains an `app/senders/` bullet
(and the `notifications.py` bullet notes the sender dispatch); `README.md`/website
feature blurbs; `DEPLOYMENT.md` + `.env.example` per §4; `help.html` per §5. mypy:
add `app/senders/base.py` (and the pure adapters) to the enforced set — keep them
ORM-free so they stay type-clean.

## 8. Delivery plan — three sequential PRs (never stacked; each branched from `main` after the previous merges)

1. **PR 1 — the seam (pure refactor, no behaviour change):** `app/senders/` package
  with the `HttpJsonSender` core and its first registration, `webhook.py` (first only
  because it's the kind that proves behaviour preservation — not privileged in the
  abstraction); `kind`/`config` columns + migration + CHECK; API schemas + descriptor
  endpoint; `fire_alerts`/test-endpoint dispatch via the registry; UI kind selector
  driven by the registry (which at this point contains one kind). Green = every
  existing alert/webhook test passes untouched.
2. **PR 2 — message kinds:** Slack + Teams (each a thin `HttpJsonSender` renderer —
  this PR is the proof the core is genuinely shared) and email (+ SMTP settings, UI
  forms, help, e2e smoke, docs).
3. **PR 3 — ticketing kinds:** Jira, ServiceNow (+ `secret_ref` mechanism,
  `send_pinned_request` header support, docs). The acceptance test lands here;
  `Closes #37` goes in **this PR's body** (the bot only auto-closes from the body).

Splitting this way keeps each bot review focused (the reviewer escalates on
concurrency/invariant findings — PR 1 carries the schema CHECK from the start to
pre-empt that class), and a failure in one kind never blocks the others.

## Explicit non-goals (this issue)

- No stored secrets / secrets-manager integration (env-only stands).
- No per-kind retry/queueing beyond the existing durable pending-alert marker — a
  failed delivery is logged and retried by the same #109 recovery machinery.
- No Jira/ServiceNow bidirectional sync (status readback, dedup/update of existing
  tickets) — create-only, as scoped in the issue.
- No email digests/batching; one message per event, same as webhooks.
