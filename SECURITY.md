# Security Policy

## Supported Versions

Marvin is pre-1.0 and under active development. Security fixes are applied to the
`main` branch only; there are no separately maintained release branches yet.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately via GitHub's [private vulnerability
reporting](https://github.com/IcebergAI/marvin/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab).

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected component(s) and any relevant configuration

We aim to acknowledge reports within 5 business days and will keep you updated on
remediation progress. Please give us a reasonable opportunity to release a fix
before any public disclosure.

## Scope

**Access model.** Marvin is **per-user isolated**, not a shared fleet. Every
extension, alert destination, alert rule, and API key is owned by a single user; all
list queries filter on `user_id` ([app/routes/api.py](app/routes/api.py),
[app/routes/alerts.py](app/routes/alerts.py)) and every single-object handler
re-checks ownership after loading, returning **404 rather than 403** so that ids are
not enumerable. Any cross-user read or mutation — IDOR, privilege escalation, or a
bypass of those ownership checks — is **in scope**.

One lifecycle exception, by design: deleting a user account **orphans** that user's
extensions (`user_id` is set to NULL and they are dropped off the watchlist) so that
the fetch and alert history survives the deletion. Orphaned rows have no owner, and
because every user-scoped query matches on a concrete `user_id`, they are reachable
by nobody through the API or UI.

Also **in scope**:

- **Authentication bypass** — forging a session cookie, defeating the
  password-change session revocation (`User.password_changed_at`, see
  [app/auth.py](app/auth.py)), bypassing API-key authentication, or performing a
  write with a key marked `readonly`.
- **Webhook SSRF** ([app/webhooks.py](app/webhooks.py)) — this is a deliberate trust
  boundary. Destination URLs are checked against a scheme allowlist and a hostname
  denylist, and any address that is not global (loopback, link-local, private, or
  reserved) is rejected. Validation runs **both** at destination create/update time
  **and again at send time**, the request is then **pinned to the validated IP**
  (preserving the original `Host` header and TLS SNI), and redirects are disabled.
  A bypass of any part of that is in scope.
- **Reaching any authenticated endpoint without credentials** — i.e. anything beyond
  the public routes listed below.

The following are **intentional, by-design** and are not vulnerabilities on their own:

- **The unauthenticated surface is exactly**: `GET /healthz`, `GET /readyz`,
  `GET`/`POST /login`, and the static assets under `/static/*` (`GET` and, as
  Starlette's `StaticFiles` also serves it, `HEAD`). The ops probes are deliberately
  unauthenticated so an orchestrator can reach them; `/readyz` reports only whether
  the database is up or down and never the underlying error. Note that `/docs`,
  `/redoc`, and `/openapi.json` are **not** public — they require an authenticated
  session.
- **There are no CSRF tokens.** Protection is `SameSite=Lax` (plus `Secure` in
  production) on the session cookie, a JSON API that requires an `application/json`
  body, and Bearer tokens as the primary machine-to-machine credential. This is a
  documented trade-off, not an oversight — see the note in
  [app/auth.py](app/auth.py) and [CLAUDE.md](CLAUDE.md).
- **The session cookie is signed, not encrypted.** Its integrity is protected; the
  username inside it is readable by design.
- **Admin accounts are seeded out-of-band** (`MARVIN_ADMIN_USERNAME` /
  `MARVIN_ADMIN_PASSWORD`, on first boot only). There is **no self-registration**,
  and `is_admin` can only be set through the admin-gated `POST /api/users`. Admin is
  a **user-management** role: it does *not* grant access to other users' extensions
  or alerts. An admin's API key inherits their admin rights and can therefore create
  further admins.
- **A single application worker is mandatory.** The background scheduler is
  per-process and the login rate limiter holds process-local state
  ([app/ratelimit.py](app/ratelimit.py)). Running multiple workers is an operator
  misconfiguration — it causes duplicate alerts and weakens login throttling — not a
  vulnerability in Marvin.
- **Extension metadata is fetched from the public stores** (Chrome Web Store, VS Code
  Marketplace, Edge Add-ons). It is public data by nature.

Reports that these surfaces leak data *beyond* their intended audience — for example
an unauthenticated caller reaching one of them, or a user seeing another user's data
through one — remain in scope.

**Deployment hardening** (secret management, TLS termination, network policy, and the
reverse proxy overwriting rather than appending `X-Forwarded-For` so that the
app-level login rate limiter cannot be evaded) is the operator's responsibility; see
[DEPLOYMENT.md](DEPLOYMENT.md).
