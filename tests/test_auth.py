import pytest
from app.auth import verify_credentials, create_session_cookie, get_current_user
from unittest.mock import MagicMock


def test_verify_credentials_correct():
    assert verify_credentials("testadmin", "testpass") is True


def test_verify_credentials_wrong_password():
    assert verify_credentials("testadmin", "wrong") is False


def test_verify_credentials_wrong_username():
    assert verify_credentials("notadmin", "testpass") is False


def test_verify_credentials_both_wrong():
    assert verify_credentials("x", "y") is False


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
    assert b"MARVIN" in r.content


async def test_login_correct_credentials(anon_client):
    r = await anon_client.post(
        "/login",
        data={"username": "testadmin", "password": "testpass"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    from app.config import settings
    assert settings.session_cookie_name in r.cookies


async def test_login_wrong_credentials(anon_client):
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
