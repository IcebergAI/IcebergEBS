"""Tests for M2M API key creation, listing, revocation, and authentication."""

from datetime import datetime, timedelta, timezone

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import generate_api_key, hash_api_key
from app.config import settings
from app.models import ApiKey, User
from tests.conftest import cached_password_hash

# ---------------------------------------------------------------------------
# Key management endpoint tests
# ---------------------------------------------------------------------------


async def test_list_keys_empty(client):
    r = await client.get("/api/keys")
    assert r.status_code == 200
    assert r.json() == []


async def test_create_key_returns_raw_key_once(client):
    r = await client.post("/api/keys", json={"label": "soar-key"})
    assert r.status_code == 201
    data = r.json()
    assert data["label"] == "soar-key"
    assert data["raw_key"].startswith("ebs_")
    assert len(data["raw_key"]) > 20
    assert data["readonly"] is False
    assert "key_hash" not in data


async def test_create_readonly_key(client):
    r = await client.post("/api/keys", json={"label": "ro-key", "readonly": True})
    assert r.status_code == 201
    data = r.json()
    assert data["readonly"] is True
    assert data["raw_key"].startswith("ebs_")


async def test_list_keys_after_create_shows_metadata_only(client):
    await client.post("/api/keys", json={"label": "k1"})
    await client.post("/api/keys", json={"label": "k2", "readonly": True})
    r = await client.get("/api/keys")
    assert r.status_code == 200
    labels = [k["label"] for k in r.json()]
    assert "k1" in labels and "k2" in labels
    for k in r.json():
        assert "raw_key" not in k
        assert "key_hash" not in k


async def test_revoke_key(client):
    r = await client.post("/api/keys", json={"label": "to-revoke"})
    key_id = r.json()["id"]

    r_del = await client.delete(f"/api/keys/{key_id}")
    assert r_del.status_code == 200
    assert r_del.json() == {"ok": True}

    r_list = await client.get("/api/keys")
    assert not any(k["id"] == key_id for k in r_list.json())


async def test_revoke_nonexistent_key(client):
    r = await client.delete("/api/keys/99999")
    assert r.status_code == 404


async def test_cannot_revoke_other_users_key(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        other = User(username="other", password_hash=cached_password_hash("password1"), is_admin=False)
        s.add(other)
        await s.commit()
        await s.refresh(other)
        key = ApiKey(user_id=other.id, label="other-key", key_hash=hash_api_key(generate_api_key()))
        s.add(key)
        await s.commit()
        await s.refresh(key)
        key_id = key.id

    r = await client.delete(f"/api/keys/{key_id}")
    assert r.status_code == 404


async def test_create_key_requires_label(client):
    r = await client.post("/api/keys", json={})
    assert r.status_code == 422


async def test_create_key_rejects_empty_label(client):
    r = await client.post("/api/keys", json={"label": ""})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Bearer token authentication tests
# ---------------------------------------------------------------------------


async def test_bearer_auth_allows_api_access(api_key_client):
    r = await api_key_client.get("/api/extensions")
    assert r.status_code == 200


async def test_bearer_auth_allows_alerts_access(api_key_client):
    r = await api_key_client.get("/api/alerts/destinations")
    assert r.status_code == 200


async def test_invalid_bearer_token_returns_401_json(anon_client):
    r = await anon_client.get(
        "/api/extensions",
        headers={"Authorization": "Bearer ebs_thisisnotavalidkey"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/json")
    assert "detail" in r.json()


async def test_no_auth_returns_401_not_redirect(anon_client):
    r = await anon_client.get("/api/extensions", follow_redirects=False)
    assert r.status_code == 401
    assert "detail" in r.json()


async def test_session_cookie_still_works_on_api_routes(client):
    r = await client.get("/api/extensions")
    assert r.status_code == 200


async def test_bearer_updates_last_used_at(api_key_client, test_db, admin_user):
    await api_key_client.get("/api/extensions")
    async with AsyncSession(test_db) as s:
        keys = (await s.exec(select(ApiKey).where(ApiKey.user_id == admin_user.id))).all()
    assert any(k.last_used_at is not None for k in keys)


async def _only_key(test_db, admin_user) -> ApiKey:
    async with AsyncSession(test_db) as s:
        return (await s.exec(select(ApiKey).where(ApiKey.user_id == admin_user.id))).one()


async def test_last_used_at_write_is_throttled(api_key_client, test_db, admin_user):
    """A second request inside the throttle window must NOT re-write last_used_at.

    Throttling the per-request write keeps read-only GETs from committing on every
    call (issue #5).
    """
    await api_key_client.get("/api/extensions")
    first = (await _only_key(test_db, admin_user)).last_used_at
    assert first is not None

    await api_key_client.get("/api/extensions")
    second = (await _only_key(test_db, admin_user)).last_used_at
    assert second == first  # unchanged — write was throttled


async def test_last_used_at_rewritten_once_stale(api_key_client, test_db, admin_user):
    """Once last_used_at is older than the throttle window, the next request rewrites it."""
    from datetime import datetime, timedelta, timezone

    from app.config import settings

    await api_key_client.get("/api/extensions")
    stale = datetime.now(timezone.utc) - timedelta(seconds=settings.api_key_last_used_throttle_seconds + 5)
    async with AsyncSession(test_db) as s:
        key = (await s.exec(select(ApiKey).where(ApiKey.user_id == admin_user.id))).one()
        key.last_used_at = stale
        s.add(key)
        await s.commit()

    await api_key_client.get("/api/extensions")
    refreshed = (await _only_key(test_db, admin_user)).last_used_at
    assert refreshed is not None
    if refreshed.tzinfo is None:
        refreshed = refreshed.replace(tzinfo=timezone.utc)
    assert refreshed > stale


# ---------------------------------------------------------------------------
# Read-only key enforcement
# ---------------------------------------------------------------------------


async def test_readonly_key_allows_get(readonly_api_key_client):
    r = await readonly_api_key_client.get("/api/extensions")
    assert r.status_code == 200


async def test_readonly_key_allows_get_alerts(readonly_api_key_client):
    r = await readonly_api_key_client.get("/api/alerts/log")
    assert r.status_code == 200


async def test_readonly_key_blocks_post(readonly_api_key_client):
    r = await readonly_api_key_client.post(
        "/api/extensions", json={"store": "chrome", "extension_id": "aapbdbdomjkkjkaonfhkkikfgjllcleb"}
    )
    assert r.status_code == 403
    assert "read-only" in r.json()["detail"].lower()


async def test_readonly_key_blocks_delete(readonly_api_key_client, test_db, admin_user):
    r = await readonly_api_key_client.delete("/api/extensions/999")
    assert r.status_code == 403


async def test_bearer_key_cannot_create_key(api_key_client):
    # Key creation is session-only (#278 review): a Bearer-authenticated key must
    # not mint a replacement, or an SSO key could self-renew past its bounded
    # lifetime and persist forever, defeating offboarding containment.
    r = await api_key_client.post("/api/keys", json={"label": "renewal"})
    assert r.status_code == 401
    assert "session" in r.json()["detail"].lower()


async def test_readonly_key_blocks_creating_new_key(readonly_api_key_client):
    # Bearer key creation is rejected outright (session-only) — a read-only key is
    # doubly barred. 401 (session required), not 403 (read-only), since the Bearer
    # path never reaches the readonly check for this route now (#278 review).
    r = await readonly_api_key_client.post("/api/keys", json={"label": "new-key"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# SSO revocation controls on the bearer path (#278)
# ---------------------------------------------------------------------------


async def _sso_user_with_key(test_db, *, key_age_days: float = 0.0, username: str = "ssokey"):
    """Seed an SSO-provisioned user (no local password) owning one API key."""
    raw_key = generate_api_key()
    # Model reality: an SSO account's password_changed_at is set at provisioning,
    # before any key it later mints — so the revocation cutoff (created_at >=
    # password_changed_at) passes and the SSO-age fence is what a stale key trips.
    # Align the marker to the key's creation time; leaving it at the default "now"
    # while backdating only the key would trip the revocation fence first.
    created = datetime.now(timezone.utc) - timedelta(days=key_age_days)
    async with AsyncSession(test_db) as s:
        user = User(
            username=username,
            password_hash=None,
            oidc_subject=f"sub-{username}",
            auth_provider="authentik",
            oidc_issuer="https://idp.test/",
            role_managed_by_idp=True,
            password_changed_at=created,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        # Capture before the ApiKey commit re-expires the instance (expired attribute
        # access lazy-loads synchronously -> MissingGreenlet under asyncpg).
        user_id = user.id
        s.add(
            ApiKey(
                user_id=user_id,
                label="soar",
                key_hash=hash_api_key(raw_key),
                created_at=created,
            )
        )
        await s.commit()
    return raw_key, user_id


async def test_sso_key_older_than_cap_is_rejected(anon_client, test_db):
    # Mirrors test_sso_session_expired_is_rejected for the bearer path (#278): an
    # offboarded SSO user's key must die within the bounded lifetime, because no
    # app-side event will ever revoke it.
    raw_key, _ = await _sso_user_with_key(test_db, key_age_days=settings.api_key_sso_max_age_days + 1)
    r = await anon_client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()


async def test_sso_key_within_cap_is_accepted(anon_client, test_db):
    raw_key, _ = await _sso_user_with_key(test_db, key_age_days=1, username="ssofresh")
    r = await anon_client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert r.status_code == 200


async def test_local_key_unaffected_by_sso_cap(anon_client, test_db):
    # Local accounts keep unbounded keys — their revocation path is change_password,
    # which deletes keys outright.
    raw_key = generate_api_key()
    old = datetime.now(timezone.utc) - timedelta(days=400)
    async with AsyncSession(test_db) as s:
        # password_changed_at at/ before the key so the revocation cutoff passes —
        # the point of this test is that the SSO-age fence does not apply to a local
        # account, not that the generic revocation cutoff rejects an old key.
        user = User(
            username="localkey",
            password_hash=cached_password_hash("pw12345678"),
            password_changed_at=old,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        s.add(
            ApiKey(
                user_id=user.id,
                label="old-local",
                key_hash=hash_api_key(raw_key),
                created_at=old,
            )
        )
        await s.commit()
    r = await anon_client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert r.status_code == 200


async def test_key_minted_before_password_change_is_rejected(anon_client, test_db):
    # The password_changed_at marker is the generic revocation cutoff (#32): the
    # IdP-driven sync bumps it to revoke sessions — keys must fall with them
    # instead of surviving as a side door (#278).
    raw_key, user_id = await _sso_user_with_key(test_db, key_age_days=2, username="ssobumped")
    async with AsyncSession(test_db) as s:
        user = await s.get(User, user_id)
        user.password_changed_at = datetime.now(timezone.utc) - timedelta(days=1)
        s.add(user)
        await s.commit()
    r = await anon_client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"].lower()


async def test_key_created_sub_second_before_password_change_is_rejected(anon_client, test_db):
    # ApiKey.created_at keeps microsecond precision, so unlike the cookie cutoff
    # there is no 1s tolerance: a key minted 500ms before password_changed_at is
    # revoked, not accepted until its age cap (#278 review).
    raw_key = generate_api_key()
    base = datetime.now(timezone.utc) - timedelta(days=1)
    async with AsyncSession(test_db) as s:
        user = User(
            username="subsec",
            password_hash=None,
            oidc_subject="sub-subsec",
            auth_provider="authentik",
            oidc_issuer="https://idp.test/",
            role_managed_by_idp=True,
            password_changed_at=base + timedelta(milliseconds=500),
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        user_id = user.id
        s.add(ApiKey(user_id=user_id, label="soar", key_hash=hash_api_key(raw_key), created_at=base))
        await s.commit()
    r = await anon_client.get("/api/extensions", headers={"Authorization": f"Bearer {raw_key}"})
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"].lower()
