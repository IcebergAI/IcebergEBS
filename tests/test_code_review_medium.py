"""Regression tests for the medium-priority code-review fixes (M1–M5, D2).

Each test maps to a GitHub issue in the "Marvin — Code Review Remediation" project:
M1 #6, M2 #7, M3 #8, M4 #9, M5 #10, D2 #12.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import _session_after_password_change, create_session_cookie
from app.fetchers.base import BaseFetcher
from app.models import ApiKey, User
from app.ratelimit import LoginRateLimiter

# ───────────────────────── M1 (#6) — revocation ─────────────────────────


def test_session_after_password_change_tolerance():
    user = MagicMock()
    now = datetime.now(timezone.utc)
    user.password_changed_at = now
    # Cookie issued well before the change → invalid.
    assert _session_after_password_change(user, now - timedelta(seconds=60)) is False
    # Cookie issued after the change → valid.
    assert _session_after_password_change(user, now + timedelta(seconds=60)) is True
    # Within the 1s granularity tolerance → still valid.
    assert _session_after_password_change(user, now - timedelta(milliseconds=500)) is True


def test_session_valid_when_password_changed_at_missing():
    user = MagicMock()
    user.password_changed_at = None  # legacy row pre-migration
    assert _session_after_password_change(user, datetime.now(timezone.utc)) is True


def test_session_after_password_change_handles_naive_datetime():
    user = MagicMock()
    user.password_changed_at = datetime.now()  # naive (e.g. from SQLite)
    # Must not raise comparing aware vs naive.
    assert isinstance(_session_after_password_change(user, datetime.now(timezone.utc)), bool)


async def test_password_change_revokes_api_keys_and_bumps_marker(client, test_db, admin_user):
    # Create an API key and confirm it authenticates.
    r = await client.post("/api/keys", json={"label": "to-revoke"})
    assert r.status_code == 201
    raw_key = r.json()["raw_key"]

    before = await client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert before.status_code == 200

    # Change the password.
    r = await client.patch(
        "/api/users/me/password",
        json={"current_password": "testpass", "new_password": "newpassw0rd"},
    )
    assert r.status_code == 200

    # The bearer token is now revoked.
    after = await client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert after.status_code == 401

    async with AsyncSession(test_db) as s:
        keys = (await s.exec(select(ApiKey).where(ApiKey.user_id == admin_user.id))).all()
        user = await s.get(User, admin_user.id)
    assert keys == []
    assert user.password_changed_at is not None


# ───────────────────────── M2 (#7) — admin UI redirect ─────────────────────────


async def test_admin_ui_redirects_non_admin(test_db):
    """A non-admin hitting an HTML admin route gets a 303 redirect, not a JSON 403."""
    from httpx import ASGITransport, AsyncClient

    from app.config import settings
    from app.database import get_session
    from app.main import app

    async with AsyncSession(test_db) as s:
        from app.auth import hash_password

        regular = User(username="reg", password_hash=await hash_password("pw"), is_admin=False)
        s.add(regular)
        await s.commit()

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session
    cookie = create_session_cookie("reg")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", cookies={settings.session_cookie_name: cookie}
    ) as c:
        r = await c.get("/admin/users", follow_redirects=False)
    app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"] == "/"


async def test_admin_ui_redirects_anonymous(anon_client):
    r = await anon_client.get("/admin/users", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


# ───────────────────────── M3 (#8) — login rate limiting ─────────────────────────


def test_rate_limiter_locks_after_threshold():
    t = [1000.0]
    rl = LoginRateLimiter(max_attempts=3, window_seconds=300, lockout_seconds=60, now=lambda: t[0])
    k = rl.key("1.2.3.4", "bob")
    assert rl.retry_after(k) is None
    rl.record_failure(k)
    rl.record_failure(k)
    assert rl.retry_after(k) is None  # under threshold
    rl.record_failure(k)  # threshold reached → locked
    assert rl.retry_after(k) is not None
    # Lockout expires after the cooldown.
    t[0] += 61
    assert rl.retry_after(k) is None


def test_rate_limiter_reset_clears_failures():
    rl = LoginRateLimiter(max_attempts=2, window_seconds=300, lockout_seconds=60)
    k = rl.key("1.2.3.4", "bob")
    rl.record_failure(k)
    rl.reset(k)
    rl.record_failure(k)
    assert rl.retry_after(k) is None  # reset means only 1 failure counted


def test_rate_limiter_window_resets_failures():
    t = [0.0]
    rl = LoginRateLimiter(max_attempts=2, window_seconds=10, lockout_seconds=60, now=lambda: t[0])
    k = rl.key("1.2.3.4", "bob")
    rl.record_failure(k)
    t[0] += 11  # window elapsed
    rl.record_failure(k)  # counts as a fresh first failure
    assert rl.retry_after(k) is None


async def test_login_locks_out_after_repeated_failures(anon_client, admin_user, monkeypatch):
    fresh = LoginRateLimiter(max_attempts=3, window_seconds=300, lockout_seconds=300)
    monkeypatch.setattr("app.routes.ui.login_limiter", fresh)
    for _ in range(3):
        r = await anon_client.post(
            "/login",
            data={"username": "testadmin", "password": "wrong"},
            follow_redirects=False,
        )
        assert r.status_code == 200  # invalid creds re-render
    # Next attempt is locked out — even the correct password is refused.
    r = await anon_client.post(
        "/login",
        data={"username": "testadmin", "password": "testpass"},
        follow_redirects=False,
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers


# ───────────────────────── M4 (#9) — error sanitisation ─────────────────────────


async def test_webhook_test_hides_internal_error(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        from app.models import AlertDestination

        dest = AlertDestination(user_id=admin_user.id, label="d", target="https://hooks.example.com/x", enabled=True)
        s.add(dest)
        await s.commit()
        await s.refresh(dest)
        dest_id = dest.id

    secret = "connect to 10.1.2.3:443 failed"
    with patch("app.routes.alerts.send_webhook", new=AsyncMock(side_effect=Exception(secret))):
        r = await client.post(f"/api/alerts/destinations/{dest_id}/test")
    assert r.status_code == 502
    body = r.json()
    assert secret not in body["detail"]
    assert "10.1.2.3" not in body["detail"]


# ───────────────────────── M5 (#10) — narrow fetcher except ─────────────────────────


class _NetFailFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id):
        return MagicMock(name="meta")

    async def download_package(self, extension_id):
        raise httpx.ConnectError("connection refused")


class _BugFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id):
        return MagicMock(name="meta")

    async def download_package(self, extension_id):
        raise TypeError("programming bug in inspection path")


async def test_network_error_is_non_fatal():
    meta, pkg = await _NetFailFetcher(MagicMock()).fetch("ext")
    assert pkg is None  # network failure → best-effort, no package
    assert meta is not None


async def test_programming_error_propagates():
    with pytest.raises(TypeError):
        await _BugFetcher(MagicMock()).fetch("ext")  # bug surfaces, not swallowed


# ───────────────────────── D2 (#12) — list vs detail serializer ─────────────────────────


async def test_list_omits_threat_intel_but_detail_includes_it(api_key_client, test_db, admin_user):
    import json

    analysis = {
        "host_permissions": [],
        "findings": [],
        "external_domains": ["evil.example.com"],
        "external_urls": ["https://evil.example.com/x"],
        "network_callout_urls": ["https://evil.example.com/x"],
    }
    async with AsyncSession(test_db) as s:
        from app.models import Extension

        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="a" * 32,
            name="E",
            publisher="P",
            version="1",
            store_url="https://x",
            permissions='["storage"]',
            package_analysis=json.dumps(analysis),
            risk_score=10,
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    lst = await api_key_client.get("/api/extensions")
    assert lst.status_code == 200
    assert lst.json()["items"][0]["threat_intel_indicators"] == []  # skipped on list

    detail = await api_key_client.get(f"/api/extensions/{ext_id}")
    assert detail.status_code == 200
    assert len(detail.json()["threat_intel_indicators"]) > 0  # built on detail
