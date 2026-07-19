---
title: Security
icon: material/shield-lock
---

<p class="eyebrow">Trust &amp; safety</p>

# Security

IcebergEBS downloads and inspects untrusted third-party code on your behalf, so its
own posture matters. This page summarises the security model; the canonical policy is
[`SECURITY.md`](https://github.com/IcebergAI/IcebergEBS/blob/main/SECURITY.md) in the
repository.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security vulnerabilities. Report privately
via GitHub's [private vulnerability
reporting](https://github.com/IcebergAI/IcebergEBS/security/advisories/new) ("Report
a vulnerability" under the repository's **Security** tab). Include a description and
impact, reproduction steps (PoC if possible), and the affected component(s) and
configuration. We aim to acknowledge within **5 business days**, and ask for
reasonable time to remediate before public disclosure.

The project is pre-1.0: fixes land on `main`, and there are no maintained release
branches.

## Untrusted input by design

Package inspection is the app's most exposed surface, and it is built to stay
passive: extension code is **never executed**. Archives are read and pattern-matched
on CPU only, with hard caps on download size, entry count, uncompressed size, and
per-file size, and archive paths can never resolve outside the extraction root.
Nothing is uploaded to a third-party scanning service. See
[Risk scoring → Package inspection](scoring.md#package-inspection).

## Authentication

**Local accounts** use bcrypt at a production work factor. Login is constant-time
with respect to whether the username exists — the bcrypt cost is always paid, against
a dummy hash if necessary, so login timing cannot be used to enumerate users.
Passwords over bcrypt's 72-byte limit are **rejected**, not silently truncated.

**Sessions** are a signed cookie: `HttpOnly`, `SameSite=Lax`, and `Secure` in
production, with a server-side maximum age.

!!! note "Signed, not encrypted"
    The session cookie is signed for integrity — it is not encrypted, and the
    username in it is readable by design. Nothing confidential is stored in it.

**Revocation.** Changing a password bumps a server-side cutoff that invalidates
every session issued before it, and deletes all of that user's API keys. An
IdP-driven change to a user's admin status bumps the same cutoff, so a demotion
takes effect immediately rather than at the next session expiry.

**API keys** are shown once at creation and stored only as a hash. They can be
marked read-only.

## Single sign-on (OIDC)

Accounts are keyed on the immutable, validated **`(issuer, subject)`** pair scoped to
the configured provider — never the mutable email claim, and never an
admin-configurable adapter name. A collision is refused as an identity conflict
rather than auto-linked, and the invariant is backed by a database constraint rather
than an application check alone, so two concurrent first-logins cannot both pass.

- **Client secrets are environment-only** — never persisted to the database, exposed
  through the API or UI, or logged.
- **Group → admin mapping defaults to non-admin**, and role sync only ever touches
  accounts explicitly marked as IdP-managed. The seeded break-glass admin is
  therefore immune to IdP changes: a compromised or misconfigured directory cannot
  demote it or lock you out.
- **SSO sessions expire faster than local ones**, because an IdP-side account
  disable cannot be pushed to the app.
- The handshake uses state, nonce, and **PKCE (S256)** in a separate short-lived
  cookie.
- `AUTH_MODE=oidc` is refused unless a complete provider is configured — a
  half-finished SSO setup cannot lock every user out.

## CSRF

There are deliberately **no CSRF tokens**. The protection is layered:

1. `SameSite=Lax` (plus `Secure` in production) on the session cookie.
2. The JSON API requires an `application/json` body, which a browser cannot send
   cross-origin from a plain form, and Bearer tokens are the primary machine
   credential.
3. An **Origin/Referer check on every state-changing request** — every non-safe
   method, with `Referer` as a fallback when `Origin` is absent.

Two properties of that third layer are worth calling out: it is **not** gated on an
existing session, so the unauthenticated `POST /login` that mints the cookie is
covered too; and Bearer-token requests carry no browser `Origin` and are exempt, so
machine clients are unaffected. The OIDC callback is a `GET` and is protected by
state + nonce + PKCE instead.

Set `ICEBERG_EBS_TRUSTED_ORIGINS` only when a proxy rewrites `Host`; same-origin
deployments need no configuration.

## Headers and CSP

Caddy is the single source of truth for security headers, in both the Compose stack
and the Kubernetes sidecar:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'self';
  object-src 'none'; form-action 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: same-origin
Permissions-Policy: (camera, microphone, geolocation, payment, usb, … all denied)
```

`script-src` is a strict `'self'` — **no** `unsafe-inline`, **no** `unsafe-eval`, and
no hash allowances. Every asset is self-hosted (no CDN), the frontend uses the
CSP-safe Alpine build, and there are no inline scripts anywhere in the templates.
This is enforced two ways in CI: a static test rejects inline `<script>` and `on*=`
handlers across every template and checks the Caddy config and its Kubernetes mirror
have not drifted, and a browser-based job boots the full stack and **fails on any
console error**, which is how a CSP violation that only manifests at runtime gets
caught.

## Rate limiting

Because Caddy has no rate-limiting directive, throttling is app-side.

- **Login lockout is always on.** Repeated failures for the same client and username
  trigger a temporary lockout with a `Retry-After`, reset on success.
- **Request-rate limiting** for `/api/*` and `POST /login` is available behind two
  independent switches — separate on purpose, so turning off API throttling cannot
  silently disable login brute-force protection. Both are **enabled in the shipped
  Compose and Helm production configuration**; they default to off so that test runs
  are not throttled.

The OIDC callback is deliberately exempt — a 429 there would burn a single-use
authorization code.

Limiter state is in-process and bounded, which is sound only because a single worker
is mandatory. Client IP comes from the canonical `X-Forwarded-For` that the proxy
**overwrites** — a proxy that appends instead would let a forged header evade per-IP
limits.

## Outbound requests

**Webhook SSRF.** Destination URLs are validated at create/update time **and again
at send time**. Validation covers the scheme, a hostname denylist that also matches
subdomains, and IP-range checks that reject anything not globally routable
(loopback, link-local, and reserved ranges included).

The send path then **connects to the validated IP directly**, preserving the original
hostname for the `Host` header and TLS SNI. That closes the DNS-rebinding window
between validating a name and requesting it. Redirects are disabled, so a `3xx`
cannot bounce the POST to an internal address.

Error messages on these paths are **generic**. A raw exception can carry a resolved
IP or an internal hostname, so the detail is logged server-side and the caller gets
"failed to deliver" — the endpoint is not an oracle for your internal network.

**Outbound proxy credentials** are environment-only. They are never written to the
database, returned by the API, rendered in a template, or logged — a resolved proxy
URL carries them in its userinfo, so exception text is scrubbed of both raw and
URL-encoded forms before it reaches a log line. The connectivity test accepts only
server-known target *labels*, never a URL, and reports only a status or an exception
class name. A webhook-origin test dials the **origin only**: the path of a
Slack-style webhook is a capability token and must not reach the wire on a test.

## Deployment posture

- Containers run **non-root**, with all capabilities dropped, a **read-only root
  filesystem**, `no-new-privileges`, and `seccompProfile: RuntimeDefault` in
  Kubernetes.
- The production image is built with `--no-dev`, so test and static-analysis tooling
  cannot reach the container. The documented verification step is that
  `import pytest` **fails** inside it.
- Release images ship with an SBOM and SLSA provenance and are **signed with
  cosign** — see [Deployment → Which image to deploy](deployment.md#which-image-to-deploy).
- The Kubernetes chart defaults to a **default-deny NetworkPolicy** with explicitly
  named hops.

## Continuous checks

Every pull request must pass blocking jobs for tests, linting, type checking,
`bandit` plus `pip-audit` against the exact locked runtime dependency set, workflow
linting (`zizmor` + `actionlint`), and the browser smoke test. CodeQL runs as the SAST
workflow, and Dependabot opens grouped weekly dependency updates across Python,
GitHub Actions, and container images. All GitHub Actions are **SHA-pinned**.

## Known limits

Stated plainly, because a security page that only lists strengths is not useful:

- **Admin is a user-management role**, not a data-isolation boundary. An admin can
  create further admins, and an admin's API key inherits those rights.
- **Horizontal scaling is not supported.** Rate-limiter state and the scheduler are
  process-local; running multiple workers weakens login throttling and duplicates
  alerts.
- **Risk scoring is a signal, not a verdict.** Inspection is pattern-based, not
  semantic, and is defeatable by deliberate obfuscation. Use it to triage what
  deserves human review — not as proof an extension is safe.
