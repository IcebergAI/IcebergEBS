from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import hash_password
from app.models import User


async def test_list_users_admin(client):
    r = await client.get("/api/users")
    assert r.status_code == 200
    users = r.json()
    assert isinstance(users, list)
    assert any(u["username"] == "testadmin" for u in users)


async def test_list_users_requires_admin(client, test_db):
    # Create a regular (non-admin) user and log in as them
    async with AsyncSession(test_db) as s:
        regular = User(username="regularuser", password_hash=await hash_password("pw"), is_admin=False)
        s.add(regular)
        await s.commit()

    from httpx import ASGITransport, AsyncClient

    from app.auth import create_session_cookie
    from app.config import settings
    from app.database import get_session
    from app.main import app

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session
    cookie = create_session_cookie("regularuser")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={settings.session_cookie_name: cookie},
    ) as c:
        r = await c.get("/api/users")
    app.dependency_overrides.clear()

    assert r.status_code == 403


async def test_create_user(client):
    r = await client.post(
        "/api/users",
        json={
            "username": "newuser",
            "password": "securepass",
            "email": "new@example.com",
        },
    )
    assert r.status_code == 201
    data = r.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"
    assert data["is_admin"] is False


async def test_create_user_duplicate(client):
    await client.post("/api/users", json={"username": "dupeuser", "password": "password123"})
    r = await client.post("/api/users", json={"username": "dupeuser", "password": "password123"})
    assert r.status_code == 409


async def test_delete_user(client):
    r = await client.post("/api/users", json={"username": "todelete", "password": "password123"})
    uid = r.json()["id"]

    r_del = await client.delete(f"/api/users/{uid}")
    assert r_del.status_code == 200
    assert r_del.json() == {"ok": True}

    r_list = await client.get("/api/users")
    assert not any(u["id"] == uid for u in r_list.json())


async def test_cannot_delete_self(client, admin_user):
    r = await client.delete(f"/api/users/{admin_user.id}")
    assert r.status_code == 400


async def test_delete_nonexistent_user(client):
    r = await client.delete("/api/users/99999")
    assert r.status_code == 404


async def test_change_password(client):
    r = await client.patch(
        "/api/users/me/password",
        json={
            "current_password": "testpass",
            "new_password": "newpass123",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}


async def test_change_password_wrong_current(client):
    r = await client.patch(
        "/api/users/me/password",
        json={
            "current_password": "wrongpass",
            "new_password": "newpass123",
        },
    )
    assert r.status_code == 400


async def test_change_password_unauthenticated_returns_401(anon_client):
    """The /api password route must return 401, not a 303 redirect to /login."""
    r = await anon_client.patch(
        "/api/users/me/password",
        json={"current_password": "x", "new_password": "newpass123"},
        follow_redirects=False,
    )
    assert r.status_code == 401


async def test_delete_user_preserves_history(client, test_db, admin_user):
    """Deleting a user removes their config rows (rules, destinations, keys) but
    preserves the forensic trail: AlertLog / FetchLog / InstallCountHistory survive,
    and the extensions are orphaned (user_id nulled, dropped from the watchlist)
    rather than hard-deleted (#28)."""
    from app.models import (
        AlertDestination,
        AlertLog,
        AlertRule,
        ApiKey,
        Extension,
        FetchLog,
        InstallCountHistory,
    )

    async with AsyncSession(test_db) as s:
        victim = User(username="victim", password_hash=await hash_password("pw"), is_admin=False)
        s.add(victim)
        await s.commit()
        await s.refresh(victim)
        vid = victim.id

        ext = Extension(
            user_id=vid,
            store="chrome",
            extension_id="victim.ext",
            name="V",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
        )
        dest = AlertDestination(user_id=vid, label="hook", target="https://hooks.example.com/v")
        s.add(ext)
        s.add(dest)
        s.add(ApiKey(user_id=vid, label="k", key_hash="deadbeef"))
        await s.commit()
        await s.refresh(ext)
        await s.refresh(dest)
        ext_id, dest_id = ext.id, dest.id

        rule = AlertRule(user_id=vid, destination_id=dest_id, extension_id=ext_id, event_type="new_version")
        s.add(rule)
        s.add(FetchLog(extension_id=ext_id, success=True))
        s.add(InstallCountHistory(extension_id=ext_id, install_count=5))
        await s.commit()
        await s.refresh(rule)
        rule_id = rule.id

        s.add(
            AlertLog(
                rule_id=rule_id,
                destination_id=dest_id,
                extension_id=ext_id,
                user_id=vid,
                event_type="new_version",
                detail="{}",
                success=True,
            )
        )
        # An orphaned log owned only via user_id (rule_id null) — the old loop missed these.
        s.add(
            AlertLog(
                rule_id=None,
                destination_id=dest_id,
                extension_id=ext_id,
                user_id=vid,
                event_type="new_version",
                detail="{}",
                success=True,
            )
        )
        await s.commit()

    r_del = await client.delete(f"/api/users/{vid}")
    assert r_del.status_code == 200

    async with AsyncSession(test_db) as s:
        # User + their config rows are gone.
        assert await s.get(User, vid) is None
        assert (await s.exec(select(AlertRule).where(AlertRule.user_id == vid))).all() == []
        assert (await s.exec(select(AlertDestination).where(AlertDestination.user_id == vid))).all() == []
        assert (await s.exec(select(ApiKey).where(ApiKey.user_id == vid))).all() == []

        # Extensions are orphaned, not deleted: owner nulled, off the watchlist.
        orphan = await s.get(Extension, ext_id)
        assert orphan is not None
        assert orphan.user_id is None
        assert orphan.watchlist is False

        # History is preserved; AlertLog rows survive with severed FKs.
        assert len((await s.exec(select(FetchLog).where(FetchLog.extension_id == ext_id))).all()) == 1
        assert (
            len((await s.exec(select(InstallCountHistory).where(InstallCountHistory.extension_id == ext_id))).all())
            == 1
        )
        logs = (await s.exec(select(AlertLog).where(AlertLog.extension_id == ext_id))).all()
        assert len(logs) == 2
        for log in logs:
            assert log.user_id is None
            assert log.rule_id is None
            assert log.destination_id is None


async def test_user_isolation(client, test_db):
    """User A cannot see User B's extensions through list endpoint."""

    from app.models import Extension

    # Create user B
    async with AsyncSession(test_db) as s:
        user_b = User(username="userb", password_hash=await hash_password("pw"), is_admin=False)
        s.add(user_b)
        await s.commit()
        await s.refresh(user_b)
        # Add extension for user B directly
        ext_b = Extension(
            user_id=user_b.id,
            store="vscode",
            extension_id="b.ext",
            name="B Extension",
            publisher="b",
            version="1.0",
            store_url="https://example.com",
        )
        s.add(ext_b)
        await s.commit()

    # Admin (user A) should not see user B's extension
    r = await client.get("/api/extensions")
    assert r.status_code == 200
    ext_ids = [e["extension_id"] for e in r.json()["items"]]
    assert "b.ext" not in ext_ids
