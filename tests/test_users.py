from unittest.mock import patch

import pytest
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
        regular = User(username="regularuser", password_hash=hash_password("pw"), is_admin=False)
        s.add(regular)
        await s.commit()

    from app.auth import create_session_cookie
    from app.config import settings
    from app.main import app
    from app.database import get_session
    from httpx import ASGITransport, AsyncClient

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
    r = await client.post("/api/users", json={
        "username": "newuser",
        "password": "securepass",
        "email": "new@example.com",
    })
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
    r = await client.patch("/api/users/me/password", json={
        "current_password": "testpass",
        "new_password": "newpass123",
    })
    assert r.status_code == 200
    assert r.json() == {"ok": True}


async def test_change_password_wrong_current(client):
    r = await client.patch("/api/users/me/password", json={
        "current_password": "wrongpass",
        "new_password": "newpass123",
    })
    assert r.status_code == 400


async def test_user_isolation(client, test_db):
    """User A cannot see User B's extensions through list endpoint."""
    from app.models import Extension
    from app.auth import create_session_cookie
    from app.config import settings
    from app.main import app
    from app.database import get_session
    from httpx import ASGITransport, AsyncClient

    # Create user B
    async with AsyncSession(test_db) as s:
        user_b = User(username="userb", password_hash=hash_password("pw"), is_admin=False)
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
    ext_ids = [e["extension_id"] for e in r.json()]
    assert "b.ext" not in ext_ids
