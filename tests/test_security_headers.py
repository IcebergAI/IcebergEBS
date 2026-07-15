"""Regression tests for #66: app-layer HSTS/CSP baseline (defense-in-depth)."""

import re
from pathlib import Path

from app.config import settings

_NGINX_HEADERS = Path(__file__).resolve().parent.parent / "nginx" / "security_headers.conf"


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
    # The proxy hides the app's upstream CSP (proxy_hide_header) and emits its own
    # canonical one. Hiding the upstream copy must not silently drop a baseline
    # directive — nginx's canonical CSP has to carry every directive _BASELINE_CSP
    # sets (notably object-src 'none', which default-src 'self' does NOT cover).
    from app.main import _BASELINE_CSP

    conf = _NGINX_HEADERS.read_text()
    assert "proxy_hide_header Content-Security-Policy;" in conf
    # Extract nginx's canonical CSP value (the add_header Content-Security-Policy line).
    m = re.search(r'add_header Content-Security-Policy "([^"]*)"', conf)
    assert m, "nginx canonical CSP add_header not found"
    nginx_csp = m.group(1)
    for directive in (d.strip() for d in _BASELINE_CSP.split(";") if d.strip()):
        assert directive in nginx_csp, f"nginx CSP missing baseline directive: {directive!r}"


async def test_hsts_present_when_secure_cookies_enabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", True)
    resp = await client.get("/healthz")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


async def test_hsts_absent_when_secure_cookies_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", False)
    resp = await client.get("/healthz")
    assert "Strict-Transport-Security" not in resp.headers
