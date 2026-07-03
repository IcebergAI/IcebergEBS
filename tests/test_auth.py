from unittest.mock import MagicMock

from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import create_session_cookie, get_current_user, verify_credentials
from app.models import User


async def test_verify_credentials_correct(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        user = await verify_credentials("testadmin", "testpass", session)
    assert user is not None
    assert user.username == "testadmin"


async def test_verify_credentials_wrong_password(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        result = await verify_credentials("testadmin", "wrong", session)
    assert result is None


async def test_verify_credentials_wrong_username(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        result = await verify_credentials("notadmin", "testpass", session)
    assert result is None


async def test_verify_credentials_both_wrong(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        result = await verify_credentials("x", "y", session)
    assert result is None


def test_get_current_user_valid_cookie():
    from app.config import settings

    token = create_session_cookie("testadmin")
    request = MagicMock()
    request.cookies.get = lambda k, default=None: token if k == settings.session_cookie_name else default
    assert get_current_user(request) == "testadmin"


def test_get_current_user_no_cookie():
    request = MagicMock()
    request.cookies.get = lambda k: None
    assert get_current_user(request) is None


def test_get_current_user_bad_cookie():
    request = MagicMock()
    request.cookies.get = lambda k: "notavalidtoken"
    assert get_current_user(request) is None


async def test_login_get(anon_client):
    r = await anon_client.get("/login")
    assert r.status_code == 200
    assert b"Sign in" in r.content


async def test_login_correct_credentials(anon_client, admin_user):
    r = await anon_client.post(
        "/login",
        data={"username": "testadmin", "password": "testpass"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    from app.config import settings

    assert settings.session_cookie_name in r.cookies


async def test_login_wrong_credentials(anon_client, admin_user):
    r = await anon_client.post(
        "/login",
        data={"username": "testadmin", "password": "badpass"},
        follow_redirects=False,
    )
    assert r.status_code == 200  # re-render, not redirect
    assert b"Invalid credentials" in r.content
    from app.config import settings

    assert settings.session_cookie_name not in r.cookies


async def test_protected_route_without_auth(anon_client):
    r = await anon_client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


async def test_protected_route_with_auth(client):
    r = await client.get("/")
    assert r.status_code == 200


async def test_logout(client):
    r = await client.post("/logout", follow_redirects=False)
    assert r.status_code == 303
    from app.config import settings

    assert settings.session_cookie_name not in r.cookies or r.cookies[settings.session_cookie_name] == ""


async def test_login_page_valid_cookie_redirects_home(anon_client, admin_user):
    # A genuinely valid session cookie should skip the login form and go to "/".
    from app.config import settings

    anon_client.cookies.set(settings.session_cookie_name, create_session_cookie("testadmin"))
    r = await anon_client.get("/login", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"


async def test_login_page_stale_cookie_renders_form(anon_client, admin_user, test_db):
    # Regression (#73): a signature-valid cookie issued before the user's last
    # password change must render the login form (200), NOT redirect to "/".
    # require_auth rejects such a cookie, so redirecting here would loop forever.
    from datetime import datetime, timedelta, timezone

    from app.config import settings

    anon_client.cookies.set(settings.session_cookie_name, create_session_cookie("testadmin"))
    # Bump password_changed_at past the cookie's issued-at (beyond the 1s tolerance).
    async with AsyncSession(test_db) as s:
        user = await s.get(User, admin_user.id)
        user.password_changed_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        s.add(user)
        await s.commit()

    r = await anon_client.get("/login", follow_redirects=False)
    assert r.status_code == 200
    assert b"Sign in" in r.content
    # The stale cookie is cleared so it can't keep failing require_auth.
    assert settings.session_cookie_name in r.headers.get("set-cookie", "")


async def test_login_page_deleted_user_cookie_renders_form(anon_client, admin_user, test_db):
    # Regression (#73): a valid cookie for a since-deleted user must render the
    # form (200), not redirect to "/" (which require_auth would bounce back).
    from app.config import settings

    anon_client.cookies.set(settings.session_cookie_name, create_session_cookie("testadmin"))
    async with AsyncSession(test_db) as s:
        user = await s.get(User, admin_user.id)
        await s.delete(user)
        await s.commit()

    r = await anon_client.get("/login", follow_redirects=False)
    assert r.status_code == 200
    assert b"Sign in" in r.content
