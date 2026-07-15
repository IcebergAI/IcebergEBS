"""Regression tests for #107: CSRF origin-check middleware (defence-in-depth)."""

from types import SimpleNamespace

from app.middleware import origin_allowed


def test_origin_allowed_helper():
    req = SimpleNamespace(url=SimpleNamespace(scheme="https", netloc="app.example"))
    assert origin_allowed("https://app.example", req, frozenset()) is True
    assert origin_allowed("https://evil.example", req, frozenset()) is False
    # Trusted-origin escape hatch for proxy Host rewrites.
    assert origin_allowed("https://trusted.example", req, frozenset({"https://trusted.example"})) is True


async def test_cookie_state_change_cross_origin_blocked(client):
    resp = await client.post("/api/extensions", headers={"Origin": "http://evil.example"}, json={})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Origin check failed"


async def test_cookie_state_change_missing_origin_blocked(client):
    # httpx lets us clear the default Origin the fixture sets.
    resp = await client.post("/api/extensions", headers={"Origin": ""}, json={})
    assert resp.status_code == 403


async def test_cookie_state_change_same_origin_allowed(client):
    # Same-origin (the fixture sets Origin: http://test) clears the CSRF gate; the route
    # then handles the body — anything but the origin-check 403.
    resp = await client.post("/api/extensions", json={})
    assert not (resp.status_code == 403 and resp.json().get("detail") == "Origin check failed")


async def test_safe_method_never_origin_checked(client):
    resp = await client.get("/api/extensions", headers={"Origin": "http://evil.example"})
    assert resp.status_code == 200


async def test_bearer_request_exempt_from_origin_check(api_key_client):
    # Bearer M2M requests carry no session cookie, so the origin check never applies.
    resp = await api_key_client.post("/api/extensions", headers={"Origin": "http://evil.example"}, json={})
    assert not (resp.status_code == 403 and resp.json().get("detail") == "Origin check failed")


async def test_login_cross_origin_blocked(anon_client):
    # Login CSRF: a cross-origin POST /login (no session cookie yet) must be rejected,
    # not silently accepted into a new authenticated session. The check is not gated on
    # an existing cookie, so this cookieless request is still covered.
    resp = await anon_client.post(
        "/login",
        headers={"Origin": "http://evil.example"},
        data={"username": "x", "password": "y"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Origin check failed"


async def test_login_same_origin_reaches_handler(anon_client):
    # Same-origin login clears the CSRF gate and reaches the login handler (bad creds
    # → 401/200/redirect, anything but the origin-check 403).
    resp = await anon_client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code != 403
