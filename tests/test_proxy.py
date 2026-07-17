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

from app import proxy
from app.auth import hash_password
from app.config import settings
from app.fetchers.transport import ProxyRoutingTransport, RetryTransport
from app.models import AlertDestination, ProxySettings, User

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
        s.add(User(username="plainuser", password_hash=await hash_password("pw"), is_admin=False))
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


async def test_get_settings_seeds_from_env_without_credentials(client, monkeypatch):
    monkeypatch.setattr(settings, "proxy_mode", "explicit")
    monkeypatch.setattr(settings, "proxy_url", "http://seeded:3128")
    monkeypatch.setattr(settings, "proxy_no_proxy", "localhost")
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


@respx.mock
async def test_test_endpoint_webhook_target_dials_origin_only(client, test_db, admin_user):
    dest = AlertDestination(
        user_id=admin_user.id,
        label="SOC Slack",
        target="https://hooks.slack.com/services/T000/B000/secrettoken",
    )
    async with AsyncSession(test_db) as s:
        s.add(dest)
        await s.commit()
        await s.refresh(dest)
    dest_id = dest.id

    await client.put("/api/proxy/settings", json={"mode": "NONE"})
    route = respx.get("https://hooks.slack.com/").mock(return_value=httpx.Response(302))
    r = await client.post("/api/proxy/test", json={"target": f"Webhook: SOC Slack (#{dest_id})"})
    assert r.status_code == 200
    assert route.called
    # The capability path must never be dialled.
    assert str(route.calls[0].request.url) == "https://hooks.slack.com/"


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


async def test_singleton_row_created_once(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "none")
    async with AsyncSession(test_db) as s:
        row1 = await proxy_settings.get_settings(s)
        row2 = await proxy_settings.get_settings(s)
    assert row1.id == 1
    assert row2.id == 1
    assert row1.mode == "NONE"

    async with AsyncSession(test_db) as s:
        rows = (await s.exec(select(ProxySettings))).all()
    assert len(rows) == 1


async def test_junk_seed_mode_normalises_to_system(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "garbage")
    async with AsyncSession(test_db) as s:
        row = await proxy_settings.get_settings(s)
    assert row.mode == "SYSTEM"


async def test_refresh_cache_loads_snapshot(test_db, monkeypatch):
    from app import proxy_settings

    monkeypatch.setattr(settings, "proxy_mode", "none")
    assert proxy.get_config() is None
    async with AsyncSession(test_db) as s:
        await proxy_settings.refresh_cache(s)
    cfg = proxy.get_config()
    assert cfg is not None
    assert cfg.mode == "NONE"
