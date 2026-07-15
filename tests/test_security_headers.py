"""Regression tests for #66: app-layer HSTS/CSP baseline (defense-in-depth)."""

from app.config import settings


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


async def test_hsts_present_when_secure_cookies_enabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", True)
    resp = await client.get("/healthz")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


async def test_hsts_absent_when_secure_cookies_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "secure_cookies", False)
    resp = await client.get("/healthz")
    assert "Strict-Transport-Security" not in resp.headers
