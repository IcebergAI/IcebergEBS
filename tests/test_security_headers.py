"""Regression tests for #66: app-layer HSTS/CSP baseline (defense-in-depth)."""

import re
from pathlib import Path

from app.config import settings

_CADDY_HEADERS = Path(__file__).resolve().parent.parent / "caddy" / "headers.caddy"


async def test_baseline_security_headers_present(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    # Existing headers still set.
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    # New app-layer CSP baseline.
    csp = resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "object-src 'none'" in csp
    assert "form-action 'self'" in csp


def test_baseline_csp_omits_script_and_default_src():
    # The baseline must NOT set script-src/default-src: emitted alongside the proxy's
    # full CSP, the browser enforces both and the most-restrictive intersection would
    # block the proxy-allowed CDN assets. Keep it purely additive.
    from app.main import _BASELINE_CSP

    assert "script-src" not in _BASELINE_CSP
    assert "default-src" not in _BASELINE_CSP


def test_proxy_canonical_csp_covers_baseline_directives():
    # Caddy SETs (replaces) the CSP with its own canonical one, overriding the app's
    # upstream baseline copy so exactly one value reaches the client (verified at runtime;
    # Caddy's `header` set replaces rather than appends). That canonical CSP must carry
    # every directive _BASELINE_CSP sets — notably object-src 'none', which default-src
    # 'self' does NOT cover — or the replace would silently drop a baseline protection.
    from app.main import _BASELINE_CSP

    conf = _CADDY_HEADERS.read_text()
    # Extract Caddy's canonical CSP value (the Content-Security-Policy line in the header block).
    m = re.search(r'Content-Security-Policy "([^"]*)"', conf)
    assert m, "Caddy canonical CSP not found in caddy/headers.caddy"
    caddy_csp = m.group(1)
    for directive in (d.strip() for d in _BASELINE_CSP.split(";") if d.strip()):
        assert directive in caddy_csp, f"Caddy CSP missing baseline directive: {directive!r}"


async def test_hsts_present_when_secure_cookies_enabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", True)
    resp = await client.get("/healthz")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


async def test_hsts_absent_when_secure_cookies_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", False)
    resp = await client.get("/healthz")
    assert "Strict-Transport-Security" not in resp.headers
