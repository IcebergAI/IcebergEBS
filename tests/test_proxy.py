"""Outbound-proxy tests (#216): resolver semantics, the routing transport, the
webhook/pinned-IP interplay, and the admin API + page.

Credentials must never escape: the resolver injects them into the proxy URL at
resolution time only, the API never accepts or returns them, and error paths
surface exception class names, not messages.
"""

import httpx
import pytest
import respx
from pydantic import SecretStr
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import proxy, proxy_settings
from app.config import settings
from app.fetchers.transport import ProxyRoutingTransport, RetryTransport
from app.models import AlertDestination, ProxySettings, User
from tests.conftest import cached_password_hash

_ENV_PROXY_VARS = [
    name.upper() if upper else name
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
    for upper in (False, True)
]


@pytest.fixture(autouse=True)
def _reset_proxy_snapshot():
    """Each test starts and ends with an unloaded snapshot (direct routing)."""
    proxy.set_config(None)
    yield
    proxy.set_config(None)


@pytest.fixture
def no_env_proxy(monkeypatch):
    """Strip ambient proxy env vars so SYSTEM-mode tests are deterministic."""
    for var in _ENV_PROXY_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def no_credentials(monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "")
    monkeypatch.setattr(settings, "proxy_password", SecretStr(""))


# ---------------------------------------------------------------------------
# Resolver: mode rules
# ---------------------------------------------------------------------------


def test_none_mode_is_direct(no_env_proxy):
    cfg = proxy.ProxyConfig(mode="NONE", proxy_url="http://proxy:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") is None


def test_explicit_mode_uses_proxy(no_credentials):
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://proxy:3128"


def test_explicit_mode_without_url_is_direct():
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") is None


def test_explicit_mode_lowercase_spelling_accepted(no_credentials):
    cfg = proxy.ProxyConfig(mode="explicit", proxy_url="http://proxy:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://proxy:3128"


def test_unknown_mode_falls_back_to_system(monkeypatch, no_env_proxy):
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:8080")
    cfg = proxy.ProxyConfig(mode="whatever", proxy_url="http://proxy:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://envproxy:8080"


def test_route_for_unloaded_snapshot_is_direct(monkeypatch):
    # Even with an ambient env proxy, an unloaded snapshot means pre-feature
    # behaviour: direct.
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:8080")
    proxy.set_config(None)
    assert proxy.route_for("https://example.com/x") is None


def test_route_for_uses_snapshot(no_credentials):
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128"))
    assert proxy.route_for("https://example.com/x") == "http://proxy:3128"


# ---------------------------------------------------------------------------
# Resolver: SYSTEM mode env parsing
# ---------------------------------------------------------------------------


def test_system_no_env_is_direct(no_env_proxy):
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") is None


@pytest.mark.parametrize("var", ["https_proxy", "HTTPS_PROXY"])
def test_system_https_target_uses_https_proxy(monkeypatch, no_env_proxy, var):
    monkeypatch.setenv(var, "http://envproxy:8080")
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://envproxy:8080"
    # An http target must not use the https proxy.
    assert proxy.resolve_proxy_url(cfg, "http://example.com/x") is None


@pytest.mark.parametrize("var", ["http_proxy", "HTTP_PROXY"])
def test_system_http_target_uses_http_proxy(monkeypatch, no_env_proxy, var):
    monkeypatch.setenv(var, "http://envproxy:8080")
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "http://example.com/x") == "http://envproxy:8080"
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") is None


def test_system_all_proxy_fallback(monkeypatch, no_env_proxy):
    monkeypatch.setenv("ALL_PROXY", "http://envproxy:8080")
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://envproxy:8080"
    assert proxy.resolve_proxy_url(cfg, "http://example.com/x") == "http://envproxy:8080"


def test_system_scheme_proxy_beats_all_proxy(monkeypatch, no_env_proxy):
    monkeypatch.setenv("https_proxy", "http://specific:8080")
    monkeypatch.setenv("all_proxy", "http://fallback:8080")
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://specific:8080"


def test_system_honours_no_proxy_env(monkeypatch, no_env_proxy):
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:8080")
    monkeypatch.setenv("NO_PROXY", "example.com,10.0.0.0/8")
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://sub.example.com/x") is None
    assert proxy.resolve_proxy_url(cfg, "https://other.org/x") == "http://envproxy:8080"


def test_system_never_injects_configured_credentials(monkeypatch, no_env_proxy):
    # An env proxy URL may carry its own userinfo; the ICEBERG_EBS_PROXY_* creds
    # belong to the EXPLICIT proxy only.
    monkeypatch.setenv("HTTPS_PROXY", "http://envproxy:8080")
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr("hunter2"))
    cfg = proxy.ProxyConfig(mode="SYSTEM")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://envproxy:8080"


# ---------------------------------------------------------------------------
# Resolver: NO_PROXY semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "entries", "bypassed"),
    [
        ("anything.example.com", ["*"], True),
        ("example.com", ["example.com"], True),
        ("sub.example.com", ["example.com"], True),
        ("sub.example.com", [".example.com"], True),
        ("notexample.com", ["example.com"], False),
        ("EXAMPLE.com", ["example.com"], True),
        ("example.com", ["EXAMPLE.COM"], True),
        ("10.1.2.3", ["10.0.0.0/8"], True),
        ("11.1.2.3", ["10.0.0.0/8"], False),
        ("192.168.1.5", ["192.168.1.5"], True),
        ("example.com", ["10.0.0.0/8"], False),
        ("10.1.2.3", ["not-a-cidr/xx", "10.0.0.0/8"], True),  # malformed entry skipped
        (None, ["example.com"], True),  # unknown host goes direct
        ("localhost", ["localhost"], True),
        ("example.com", [], False),
    ],
)
def test_should_bypass(host, entries, bypassed):
    assert proxy._should_bypass(host, entries) is bypassed


def test_explicit_bypasses_no_proxy_target(no_credentials):
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128", no_proxy="localhost,.corp.example.com")
    assert proxy.resolve_proxy_url(cfg, "https://git.corp.example.com/x") is None
    assert proxy.resolve_proxy_url(cfg, "https://chromewebstore.google.com/x") == "http://proxy:3128"


# ---------------------------------------------------------------------------
# Webhook interplay: send_webhook pins the URL netloc to a validated IP, so the
# routing decision runs against the IP — bypass needs IP/CIDR entries.
# ---------------------------------------------------------------------------


def test_pinned_ip_url_matches_cidr_no_proxy(no_credentials):
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128", no_proxy="198.51.100.0/24")
    assert proxy.resolve_proxy_url(cfg, "https://198.51.100.7/services/hook") is None


def test_pinned_ip_url_ignores_domain_no_proxy(no_credentials):
    # The transport sees the pinned-IP URL, so a domain entry for the original
    # hostname cannot match — documented behaviour.
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128", no_proxy="hooks.example.com")
    assert proxy.resolve_proxy_url(cfg, "https://198.51.100.7/services/hook") == "http://proxy:3128"


# ---------------------------------------------------------------------------
# Resolver: credential injection
# ---------------------------------------------------------------------------


def test_credentials_injected_url_encoded(monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr("p@ss word"))
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy.corp:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://bob:p%40ss%20word@proxy.corp:3128"


def test_username_only_injected(monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr(""))
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy.corp:3128")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://bob@proxy.corp:3128"


def test_no_credentials_url_unchanged(no_credentials):
    cfg = proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy.corp:3128/path")
    assert proxy.resolve_proxy_url(cfg, "https://example.com/x") == "http://proxy.corp:3128/path"


# ---------------------------------------------------------------------------
# Startup validation + scrubbing
# ---------------------------------------------------------------------------


def test_validate_rejects_unknown_mode(monkeypatch):
    monkeypatch.setattr(settings, "proxy_mode", "bogus")
    with pytest.raises(RuntimeError, match="PROXY_MODE"):
        proxy.validate_proxy_settings()


def test_validate_explicit_requires_url(monkeypatch):
    monkeypatch.setattr(settings, "proxy_mode", "explicit")
    monkeypatch.setattr(settings, "proxy_url", "")
    with pytest.raises(RuntimeError, match="requires ICEBERG_EBS_PROXY_URL"):
        proxy.validate_proxy_settings()


@pytest.mark.parametrize("bad_url", ["socks5://sekrit-proxy:1080", "sekrit-proxy.internal:3128", "ftp://sekrit-proxy"])
def test_validate_rejects_bad_scheme_and_never_echoes_url(monkeypatch, bad_url):
    monkeypatch.setattr(settings, "proxy_mode", "system")
    monkeypatch.setattr(settings, "proxy_url", bad_url)
    with pytest.raises(RuntimeError) as excinfo:
        proxy.validate_proxy_settings()
    # The URL may carry hand-rolled credentials — it must not appear in the error.
    assert bad_url not in str(excinfo.value)


def test_validate_accepts_defaults():
    proxy.validate_proxy_settings()  # repo defaults: system mode, no URL


def test_validate_rejects_userinfo_url_without_echoing_it(monkeypatch):
    # Env-seeded URL flows onto the API-visible DB row — userinfo would leak.
    monkeypatch.setattr(settings, "proxy_mode", "explicit")
    monkeypatch.setattr(settings, "proxy_url", "http://bob:hunter2@proxy:3128")
    with pytest.raises(RuntimeError, match="must not contain credentials") as excinfo:
        proxy.validate_proxy_settings()
    assert "hunter2" not in str(excinfo.value)


def test_scrub_redacts_raw_and_encoded_credentials(monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr("p@ss word"))
    text = "connect to http://bob:p%40ss%20word@proxy failed for bob with p@ss word"
    scrubbed = proxy.scrub(text)
    assert "bob" not in scrubbed
    assert "p@ss word" not in scrubbed
    assert "p%40ss%20word" not in scrubbed


# ---------------------------------------------------------------------------
# ProxyRoutingTransport
# ---------------------------------------------------------------------------


class _FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, proxy_url, results=None):
        self.proxy_url = proxy_url
        self.requests: list[httpx.Request] = []
        self.closed = False
        self._results = results

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._results:
            result = self._results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        return httpx.Response(200)

    async def aclose(self) -> None:
        self.closed = True


def _routing(results_by_proxy=None):
    created: list[_FakeTransport] = []

    def factory(proxy_url):
        results = (results_by_proxy or {}).get(proxy_url)
        t = _FakeTransport(proxy_url, results=list(results) if results else None)
        created.append(t)
        return t

    return created, ProxyRoutingTransport(limits=httpx.Limits(), transport_factory=factory)


async def test_routing_unloaded_snapshot_goes_direct():
    created, routing = _routing()
    resp = await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    assert resp.status_code == 200
    assert [t.proxy_url for t in created] == [None]
    assert len(created[0].requests) == 1


async def test_routing_explicit_uses_proxied_transport_with_credentials(monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr("hunter2"))
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128"))
    created, routing = _routing()
    await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    assert [t.proxy_url for t in created] == [None, "http://bob:hunter2@proxy:3128"]
    assert len(created[1].requests) == 1
    assert not created[0].requests


async def test_routing_no_proxy_target_goes_direct(no_credentials):
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128", no_proxy=".internal.corp"))
    created, routing = _routing()
    await routing.handle_async_request(httpx.Request("GET", "https://ci.internal.corp/x"))
    await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    direct, proxied = created
    assert [len(direct.requests), len(proxied.requests)] == [1, 1]
    assert proxied.proxy_url == "http://proxy:3128"


async def test_routing_proxied_transport_reused_across_requests(no_credentials):
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128"))
    created, routing = _routing()
    for _ in range(3):
        await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    assert len(created) == 2  # direct + one proxied, no rebuild per request
    assert len(created[1].requests) == 3


async def test_routing_live_edit_retires_old_transport(no_credentials):
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://old-proxy:3128"))
    created, routing = _routing()
    await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))

    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://new-proxy:3128"))
    await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))

    _, old, new = created
    assert old.proxy_url == "http://old-proxy:3128"
    assert new.proxy_url == "http://new-proxy:3128"
    # Retired, not closed — in-flight requests must be able to finish on it.
    assert old.closed is False

    await routing.aclose()
    assert all(t.closed for t in created)


async def test_routing_aclose_closes_direct_and_proxied(no_credentials):
    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128"))
    created, routing = _routing()
    await routing.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    await routing.aclose()
    assert all(t.closed for t in created)


async def test_retry_reconsults_routing_after_snapshot_swap(monkeypatch, no_credentials):
    """A retry attempt re-routes: fixing a broken proxy mid-backoff takes effect."""
    from app.fetchers import transport as tmod

    async def _no_sleep(_delay):
        return None

    monkeypatch.setattr(tmod.asyncio, "sleep", _no_sleep)

    proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://broken:3128"))
    created, routing = _routing(results_by_proxy={"http://broken:3128": [httpx.ConnectError("boom")]})
    retry = RetryTransport(routing, max_retries=2, backoff_base=0.0, backoff_cap=0.0)

    original = routing.handle_async_request

    async def _swap_after_first(request):
        try:
            return await original(request)
        except httpx.ConnectError:
            proxy.set_config(proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://fixed:3128"))
            raise

    monkeypatch.setattr(routing, "handle_async_request", _swap_after_first)

    resp = await retry.handle_async_request(httpx.Request("GET", "https://example.com/x"))
    assert resp.status_code == 200
    proxies = [t.proxy_url for t in created]
    assert "http://broken:3128" in proxies and "http://fixed:3128" in proxies


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

_API_CALLS = [
    ("GET", "/api/proxy/settings", None),
    ("PUT", "/api/proxy/settings", {"mode": "NONE"}),
    ("GET", "/api/proxy/targets", None),
    ("POST", "/api/proxy/test", {"target": "VS Code Marketplace"}),
]


@pytest.mark.parametrize(("method", "path", "body"), _API_CALLS)
async def test_proxy_api_requires_auth(anon_client, method, path, body):
    r = await anon_client.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize(("method", "path", "body"), _API_CALLS)
async def test_proxy_api_requires_admin(client, test_db, method, path, body):
    from httpx import ASGITransport, AsyncClient

    from app.auth import create_session_cookie
    from app.database import get_session
    from app.main import app

    async with AsyncSession(test_db) as s:
        s.add(User(username="plainuser", password_hash=cached_password_hash("pw"), is_admin=False))
        await s.commit()

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session
    cookie = create_session_cookie("plainuser")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={settings.session_cookie_name: cookie},
        headers={"Origin": "http://test"},
    ) as c:
        r = await c.request(method, path, json=body)
    app.dependency_overrides.clear()
    assert r.status_code == 403


async def _reseed_proxy(test_db):
    """Drop the conftest default-seed and re-seed from the current (monkeypatched)
    env — the seed reads env only when the row is missing (#234)."""
    from app import proxy_settings

    async with AsyncSession(test_db) as s:
        existing = await s.get(ProxySettings, 1)
        if existing is not None:
            await s.delete(existing)
            await s.commit()
        await proxy_settings.ensure_seeded(s)


async def test_get_settings_seeds_from_env_without_credentials(client, test_db, monkeypatch):
    monkeypatch.setattr(settings, "proxy_mode", "explicit")
    monkeypatch.setattr(settings, "proxy_url", "http://seeded:3128")
    monkeypatch.setattr(settings, "proxy_no_proxy", "localhost")
    await _reseed_proxy(test_db)
    r = await client.get("/api/proxy/settings")
    assert r.status_code == 200
    data = r.json()
    assert data["mode"] == "EXPLICIT"
    assert data["proxy_url"] == "http://seeded:3128"
    assert data["no_proxy"] == "localhost"
    assert set(data) == {"mode", "proxy_url", "no_proxy", "updated_at"}


async def test_put_settings_round_trip_refreshes_snapshot(client):
    r = await client.put(
        "/api/proxy/settings",
        json={"mode": "explicit", "proxy_url": "http://proxy:3128", "no_proxy": "localhost"},
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "EXPLICIT"  # normalised

    cfg = proxy.get_config()
    assert cfg == proxy.ProxyConfig(mode="EXPLICIT", proxy_url="http://proxy:3128", no_proxy="localhost")

    r = await client.get("/api/proxy/settings")
    assert r.json()["proxy_url"] == "http://proxy:3128"


async def test_put_settings_partial_update(client):
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    r = await client.put("/api/proxy/settings", json={"no_proxy": "10.0.0.0/8"})
    data = r.json()
    assert data["mode"] == "NONE"  # untouched by the second PUT
    assert data["no_proxy"] == "10.0.0.0/8"


async def test_put_settings_rejects_credential_keys(client):
    r = await client.put(
        "/api/proxy/settings",
        json={"mode": "NONE", "proxy_username": "bob", "proxy_password": "hunter2"},
    )
    assert r.status_code == 422


async def test_put_settings_rejects_invalid_mode(client):
    r = await client.put("/api/proxy/settings", json={"mode": "bogus"})
    assert r.status_code == 422


@pytest.mark.parametrize("bad_url", ["socks5://proxy:1080", "proxy:3128", "ftp://p"])
async def test_put_settings_rejects_invalid_url(client, bad_url):
    r = await client.put("/api/proxy/settings", json={"proxy_url": bad_url})
    assert r.status_code == 422


async def test_put_settings_allows_clearing_url(client):
    await client.put("/api/proxy/settings", json={"proxy_url": "http://proxy:3128"})
    r = await client.put("/api/proxy/settings", json={"proxy_url": ""})
    assert r.status_code == 200
    assert r.json()["proxy_url"] == ""


async def test_put_settings_rejects_userinfo_in_url(client):
    # Credentials are env-only: a userinfo URL would be persisted and echoed
    # by every subsequent GET.
    r = await client.put("/api/proxy/settings", json={"proxy_url": "http://bob:hunter2@proxy:3128"})
    assert r.status_code == 422
    r = await client.get("/api/proxy/settings")
    assert "hunter2" not in r.text


async def test_put_settings_rejects_explicit_without_url(client):
    # Switching to EXPLICIT while no URL is stored must fail, not silently go direct.
    r = await client.put("/api/proxy/settings", json={"mode": "EXPLICIT"})
    assert r.status_code == 422


async def test_put_settings_rejects_clearing_url_while_explicit(client):
    r = await client.put("/api/proxy/settings", json={"mode": "EXPLICIT", "proxy_url": "http://proxy:3128"})
    assert r.status_code == 200
    # Clearing only the URL leaves the stored mode EXPLICIT — the resulting state
    # is invalid and must be rejected (proxy-bypass, not partial update).
    r = await client.put("/api/proxy/settings", json={"proxy_url": ""})
    assert r.status_code == 422
    assert (await client.get("/api/proxy/settings")).json()["proxy_url"] == "http://proxy:3128"


async def test_put_settings_explicit_with_url_in_same_request(client):
    r = await client.put("/api/proxy/settings", json={"mode": "explicit", "proxy_url": "http://proxy:3128"})
    assert r.status_code == 200
    assert r.json()["mode"] == "EXPLICIT"


async def test_targets_are_labels_only(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        s.add(
            AlertDestination(
                user_id=admin_user.id,
                label="SOC Slack",
                target="https://hooks.slack.com/services/T000/B000/secrettoken",
            )
        )
        s.add(
            AlertDestination(
                user_id=admin_user.id,
                label="Disabled hook",
                target="https://disabled.example.com/hook",
                enabled=False,
            )
        )
        await s.commit()

    r = await client.get("/api/proxy/targets")
    assert r.status_code == 200
    targets = r.json()["targets"]
    assert "VS Code Marketplace" in targets
    assert any(t.startswith("Webhook: SOC Slack") for t in targets)
    assert not any("Disabled hook" in t for t in targets)
    # Labels only — no URL, and certainly no capability token, may appear.
    joined = " ".join(targets)
    assert "http" not in joined
    assert "secrettoken" not in joined


async def test_targets_include_enabled_idp(client):
    # #232: SSO egress (OIDC discovery/JWKS/token/userinfo) is a probeable target too.
    # conftest enables the Authentik provider, so its IdP origin must be listed —
    # by label only, never the metadata URL.
    r = await client.get("/api/proxy/targets")
    assert r.status_code == 200
    targets = r.json()["targets"]
    assert any(t.startswith("SSO: Authentik") for t in targets)
    assert "http" not in " ".join(targets)
    assert "authentik.test" not in " ".join(targets)


@respx.mock
async def test_idp_target_is_probeable(client):
    # The SSO label resolves through the server-built map (never a body URL), so the
    # /test endpoint accepts and dials it — exactly the tool an admin needs to check
    # IdP reachability. Probes the discovery origin, not the capability-free store path.
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    route = respx.get("https://authentik.test/").mock(return_value=httpx.Response(200))
    r = await client.post("/api/proxy/test", json={"target": "SSO: Authentik (IdP)"})
    assert r.status_code == 200
    assert r.json()["result"] == "ok: HTTP 200"
    assert route.called


async def test_test_endpoint_rejects_unknown_target(client):
    r = await client.post("/api/proxy/test", json={"target": "https://evil.internal/"})
    assert r.status_code == 400


@respx.mock
async def test_test_endpoint_success(client):
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    respx.get("https://marketplace.visualstudio.com/").mock(return_value=httpx.Response(200))
    r = await client.post("/api/proxy/test", json={"target": "VS Code Marketplace"})
    assert r.status_code == 200
    data = r.json()
    assert data["result"] == "ok: HTTP 200"
    assert data["via_proxy"] is False


async def _add_destination(test_db, admin_user, **kwargs) -> int:
    dest = AlertDestination(
        user_id=admin_user.id,
        label=kwargs.pop("label", "SOC Slack"),
        target=kwargs.pop("target", "https://hooks.slack.com/services/T000/B000/secrettoken"),
        **kwargs,
    )
    async with AsyncSession(test_db) as s:
        s.add(dest)
        await s.commit()
        await s.refresh(dest)
    assert dest.id is not None
    return dest.id


@respx.mock
async def test_test_endpoint_webhook_target_pins_ip_and_dials_origin_only(client, test_db, admin_user):
    from unittest.mock import AsyncMock, patch

    dest_id = await _add_destination(test_db, admin_user)
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    # The probe must apply the delivery-path SSRF treatment: resolve, validate,
    # and dial the pinned public IP with the original hostname kept for Host/SNI.
    route = respx.get("https://93.184.216.34/").mock(return_value=httpx.Response(302))
    with patch("app.webhooks._resolve_host", new=AsyncMock(return_value=["93.184.216.34"])):
        r = await client.post("/api/proxy/test", json={"target": f"Webhook: SOC Slack (#{dest_id})"})
    assert r.status_code == 200
    # Redirects are never followed — a 3xx is reported, not chased.
    assert r.json()["result"] == "ok: HTTP 302"
    assert route.called
    request = route.calls[0].request
    # Pinned-IP netloc, capability path never dialled, hostname preserved for Host.
    assert str(request.url) == "https://93.184.216.34/"
    assert request.headers["host"] == "hooks.slack.com"


async def test_test_endpoint_webhook_target_rejects_private_resolution(client, test_db, admin_user):
    from unittest.mock import AsyncMock, patch

    dest_id = await _add_destination(test_db, admin_user, label="Rebound", target="https://rebound.example.com/hook")
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    with patch("app.webhooks._resolve_host", new=AsyncMock(return_value=["10.0.0.5"])):
        r = await client.post("/api/proxy/test", json={"target": f"Webhook: Rebound (#{dest_id})"})
    assert r.status_code == 200
    # Class name only — validation failure, nothing dialled.
    assert r.json()["result"] == "error: WebhookValidationError"


@respx.mock
async def test_test_endpoint_never_follows_redirects(client):
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    respx.get("https://marketplace.visualstudio.com/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://10.0.0.5/internal"})
    )
    internal = respx.get("https://10.0.0.5/internal").mock(return_value=httpx.Response(200))
    r = await client.post("/api/proxy/test", json={"target": "VS Code Marketplace"})
    assert r.json()["result"] == "ok: HTTP 302"
    assert not internal.called


@respx.mock
async def test_test_endpoint_failure_returns_class_name_only(client, monkeypatch):
    monkeypatch.setattr(settings, "proxy_username", "bob")
    monkeypatch.setattr(settings, "proxy_password", SecretStr("hunter2"))
    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    respx.get("https://marketplace.visualstudio.com/").mock(
        side_effect=httpx.ConnectError("secret detail http://bob:hunter2@proxy")
    )
    r = await client.post("/api/proxy/test", json={"target": "VS Code Marketplace"})
    assert r.status_code == 200
    data = r.json()
    assert data["result"] == "error: ConnectError"
    assert "hunter2" not in r.text
    assert "secret detail" not in r.text


# ---------------------------------------------------------------------------
# Admin page
# ---------------------------------------------------------------------------


async def test_admin_proxy_page_renders_for_admin(client):
    r = await client.get("/admin/proxy")
    assert r.status_code == 200
    assert "Outbound proxy" in r.text
    assert "proxy-data" in r.text


async def test_admin_proxy_page_redirects_anonymous(anon_client):
    r = await anon_client.get("/admin/proxy")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


# ---------------------------------------------------------------------------
# Singleton service
# ---------------------------------------------------------------------------


async def test_ensure_seeded_idempotent_and_from_env(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "none")
    await _reseed_proxy(test_db)
    async with AsyncSession(test_db) as s:
        # Idempotent: a second call reuses the row rather than inserting a duplicate.
        row1 = await proxy_settings.ensure_seeded(s)
        row2 = await proxy_settings.ensure_seeded(s)
    assert row1.id == 1
    assert row2.id == 1
    assert row1.mode == "NONE"

    async with AsyncSession(test_db) as s:
        rows = (await s.exec(select(ProxySettings))).all()
    assert len(rows) == 1


async def test_junk_seed_mode_normalises_to_system(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "garbage")
    await _reseed_proxy(test_db)
    async with AsyncSession(test_db) as s:
        row = await proxy_settings.get_settings(s)
    assert row.mode == "SYSTEM"


async def test_refresh_cache_loads_snapshot(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "none")
    # The conftest seeds the row from the default env; re-seed from the monkeypatched
    # env so refresh_cache loads NONE into the snapshot.
    await _reseed_proxy(test_db)
    async with AsyncSession(test_db) as s:
        await proxy_settings.refresh_cache(s)
    cfg = proxy.get_config()
    assert cfg is not None
    assert cfg.mode == "NONE"


# ---------------------------------------------------------------------------
# EXPLICIT⇒URL invariant under concurrency: the validation lives in
# update_settings on the RESULTING row under a FOR UPDATE lock, with a schema
# CHECK constraint as the backstop — a route-level pre-check alone is a TOCTOU
# (two interleaved PUTs could merge into EXPLICIT-with-empty-URL = fail-open).
# ---------------------------------------------------------------------------


async def test_update_settings_rejects_resulting_invalid_state(test_db):
    from app import proxy_settings

    async with AsyncSession(test_db) as s:
        await proxy_settings.update_settings(s, {"mode": "NONE", "proxy_url": ""})
    async with AsyncSession(test_db) as s:
        with pytest.raises(ValueError, match="explicit mode requires a proxy URL"):
            await proxy_settings.update_settings(s, {"mode": "EXPLICIT"})
    async with AsyncSession(test_db) as s:
        row = await proxy_settings.get_settings(s)
    assert row.mode == "NONE"  # rejected patch rolled back, nothing committed


async def test_concurrent_updates_cannot_merge_into_explicit_without_url(test_db):
    """The bot-reported race: one writer sets mode=EXPLICIT, another clears
    proxy_url. Whatever the interleave, the loser must be rejected — the merged
    fail-open state (EXPLICIT + empty URL) must be unreachable."""
    import asyncio

    from app import proxy_settings

    async with AsyncSession(test_db) as s:
        await proxy_settings.update_settings(s, {"mode": "SYSTEM", "proxy_url": "http://proxy:3128"})

    async def set_explicit():
        async with AsyncSession(test_db) as s:
            await proxy_settings.update_settings(s, {"mode": "EXPLICIT"})

    async def clear_url():
        async with AsyncSession(test_db) as s:
            await proxy_settings.update_settings(s, {"proxy_url": ""})

    results = await asyncio.gather(set_explicit(), clear_url(), return_exceptions=True)
    # Exactly one writer must lose (ValueError), never both succeed.
    errors = [r for r in results if isinstance(r, Exception)]
    assert len(errors) == 1 and isinstance(errors[0], ValueError)

    async with AsyncSession(test_db) as s:
        row = await proxy_settings.get_settings(s)
    assert not (row.mode == "EXPLICIT" and not row.proxy_url.strip())


async def test_stale_identity_map_reader_validates_fresh_state(test_db):
    """Deterministic staging of the reported race: a session that loaded the row
    BEFORE another writer committed must not validate its stale snapshot. The
    locking get uses populate_existing=True, so the queued writer re-reads the
    winner's committed state and rejects with ValueError — without it, the stale
    SYSTEM value passes validation and the CHECK constraint turns the commit
    into an uncaught IntegrityError (500) instead of a 422."""
    from app import proxy_settings

    async with AsyncSession(test_db) as seed:
        await proxy_settings.update_settings(seed, {"mode": "SYSTEM", "proxy_url": "http://proxy:3128"})

    s1 = AsyncSession(test_db)
    s2 = AsyncSession(test_db)
    try:
        # Both sessions load the row (SYSTEM + URL) into their identity maps
        # before either takes the lock.
        await proxy_settings.get_settings(s1)
        await proxy_settings.get_settings(s2)
        # Writer 1 wins: commits EXPLICIT (URL still set — valid).
        await proxy_settings.update_settings(s1, {"mode": "EXPLICIT"})
        # Writer 2 clears the URL. Its identity map still says SYSTEM; only a
        # refreshed locked read can see EXPLICIT and reject the merge.
        with pytest.raises(ValueError, match="explicit mode requires a proxy URL"):
            await proxy_settings.update_settings(s2, {"proxy_url": ""})
    finally:
        await s1.close()
        await s2.close()

    async with AsyncSession(test_db) as s:
        row = await proxy_settings.get_settings(s)
    assert row.mode == "EXPLICIT"
    assert row.proxy_url == "http://proxy:3128"  # loser's patch fully discarded


async def test_schema_check_constraint_backstops_invariant(test_db):
    """A writer that bypasses update_settings entirely still cannot commit the
    fail-open state: the CHECK constraint rejects it at the schema level."""
    from sqlalchemy import text as sa_text
    from sqlalchemy.exc import IntegrityError

    from app import proxy_settings

    async with AsyncSession(test_db) as s:
        await proxy_settings.get_settings(s)  # seed the singleton
        with pytest.raises(IntegrityError):
            await s.execute(sa_text("UPDATE proxysettings SET mode = 'EXPLICIT', proxy_url = '' WHERE id = 1"))
        await s.rollback()


# ── Mode enum + case-insensitivity (#230) ──────────────────────────────────
# The mode CHECK was case-sensitive and didn't constrain the enum, and
# update_settings compared case-sensitively — so a lowercase 'explicit' (from a
# bypassing writer or a direct update_settings call) could commit an
# EXPLICIT-with-no-URL row that the resolver treats as direct egress: the exact
# fail-open state the guards exist to prevent.


async def test_update_settings_normalises_lowercase_mode(test_db):
    async with AsyncSession(test_db) as s:
        row = await proxy_settings.update_settings(s, {"mode": "explicit", "proxy_url": "http://proxy:3128"})
    assert row.mode == "EXPLICIT"  # normalised to the canonical spelling, not stored as 'explicit'
    async with AsyncSession(test_db) as s:
        assert (await proxy_settings.get_settings(s)).mode == "EXPLICIT"


async def test_update_settings_lowercase_explicit_without_url_is_rejected(test_db):
    """The fail-open case: 'explicit' + empty URL must not slip past the guards into a
    silently-direct EXPLICIT row — it normalises to EXPLICIT and then hits the URL guard."""
    async with AsyncSession(test_db) as s:
        with pytest.raises(ValueError, match="explicit mode requires a proxy URL"):
            await proxy_settings.update_settings(s, {"mode": "explicit"})
    async with AsyncSession(test_db) as s:
        assert (await proxy_settings.get_settings(s)).mode != "EXPLICIT"  # nothing committed


async def test_update_settings_rejects_junk_mode(test_db):
    async with AsyncSession(test_db) as s:
        with pytest.raises(ValueError, match="invalid proxy mode"):
            await proxy_settings.update_settings(s, {"mode": "nonsense"})
    async with AsyncSession(test_db) as s:
        assert (await proxy_settings.get_settings(s)).mode in ("NONE", "SYSTEM", "EXPLICIT")


async def test_schema_check_constraint_blocks_non_enum_mode(test_db):
    """DB backstop for a writer that bypasses update_settings entirely: the mode enum
    CHECK rejects a lowercase/junk value at the schema level (#230)."""
    from sqlalchemy import text as sa_text
    from sqlalchemy.exc import IntegrityError

    async with AsyncSession(test_db) as s:
        await proxy_settings.get_settings(s)  # seed the singleton
        with pytest.raises(IntegrityError):
            await s.execute(sa_text("UPDATE proxysettings SET mode = 'explicit' WHERE id = 1"))
        await s.rollback()
