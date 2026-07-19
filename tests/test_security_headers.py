"""The app-canonical security headers.

The app (``app/main.py:security_headers``) is the SINGLE source of truth for security
headers — inverting the old #66 design where Caddy SET a fuller policy over an app-side
baseline. These tests assert the canonical set on real responses (the conftest clients
run ``ASGITransport`` against the real app, so the middleware is exercised), and guard
the Caddy side of the contract: ``caddy/headers.caddy`` must stay a set-if-absent (`?`)
fallback — a hard SET reappearing at the edge would clobber the app's canonical values
(the #201 double-header bug class, inverted).
"""

import re
from pathlib import Path

from app.config import settings
from app.main import _CANONICAL_CSP, _HSTS, _PERMISSIONS_POLICY

_CADDY_HEADERS = Path(__file__).resolve().parent.parent / "caddy" / "headers.caddy"

# The fallback CSP for Caddy-generated responses (502 when the app is down, the :80
# redirect). Deliberately a tiny static deny-all — those responses render no content —
# so it never needs syncing with the app policy.
_FALLBACK_CSP = "default-src 'none'; frame-ancestors 'none'"


async def test_canonical_security_headers_present(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    assert resp.headers["Permissions-Policy"] == _PERMISSIONS_POLICY
    # The canonical CSP, exactly — the app is the owner, nothing rewrites it downstream.
    csp = resp.headers["Content-Security-Policy"]
    assert csp == _CANONICAL_CSP
    # Belt-and-braces on the load-bearing directives, so a policy-string refactor that
    # accidentally drops one fails with a readable diff rather than a giant string diff.
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src-elem 'self'",
        "style-src-attr 'unsafe-inline'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
    ):
        assert directive in csp


async def test_headers_present_on_error_responses(client):
    # security_headers is registered last → outermost, so error paths (404s, exception
    # handlers) must carry the canonical headers too.
    resp = await client.get("/no-such-path")
    assert resp.status_code == 404
    assert resp.headers["Content-Security-Policy"] == _CANONICAL_CSP
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_img_src_omits_data_uri():
    # Tightened alongside the app-side move: nothing first-party uses data: images
    # (templates, CSS sources, and the built output.css were all checked), so the
    # source must not creep back without a deliberate decision.
    assert "data:" not in _CANONICAL_CSP


def test_caddy_fallback_uses_only_set_if_absent_ops():
    # Every header op in the Caddy fallback must be `defer`, a `?` set-if-absent, or the
    # `-Server` delete. A hard SET here would run against proxied responses too and
    # clobber the app's canonical header (#201 inverted). The Helm ConfigMap mirror is
    # covered for free via tests/test_helm_caddy.py's byte-equality check.
    conf = _CADDY_HEADERS.read_text()
    block = re.search(r"header \{\n(.*?)\n\}", conf, re.DOTALL)
    assert block, "no header block found in caddy/headers.caddy"
    for line in block.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert stripped == "defer" or stripped.startswith("?") or stripped == "-Server", (
            f"caddy/headers.caddy contains a non-fallback header op: {stripped!r} — "
            "the app owns the canonical headers; edge ops must be ?-prefixed "
            "(set-if-absent) so they cannot clobber the app's values"
        )
    # The fallback CSP stays the tiny static deny-all — never synced with the app policy.
    m = re.search(r'\?Content-Security-Policy "([^"]*)"', conf)
    assert m and m.group(1) == _FALLBACK_CSP


async def test_hsts_present_when_secure_cookies_enabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", True)
    resp = await client.get("/healthz")
    assert resp.headers["Strict-Transport-Security"] == _HSTS
    assert _HSTS == "max-age=63072000; includeSubDomains; preload"


async def test_hsts_absent_when_secure_cookies_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", False)
    resp = await client.get("/healthz")
    assert "Strict-Transport-Security" not in resp.headers
