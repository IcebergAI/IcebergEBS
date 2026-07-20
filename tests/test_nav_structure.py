"""Rail grouping, the shared breadcrumb, and the single search entry point.

The rail used to render one "Admin" group holding both per-user settings (alerts,
API keys, help) and the genuinely admin-only pages, so the heading was wrong for
regular members and the two privilege levels looked identical. The split into
Account / Administration is what these tests pin, along with the two UX invariants
that are easy to regress silently: exactly one search input per page, and one
breadcrumb rendered from the shell rather than hand-rolled per page.
"""

import re

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import create_session_cookie
from app.config import settings
from app.database import get_session
from app.main import app
from app.models import User
from tests.conftest import cached_password_hash

ADMIN_LINKS = ("/admin/users", "/admin/proxy", "/admin/oidc")
ACCOUNT_LINKS = ("/account", "/account/keys", "/help")


@pytest_asyncio.fixture
async def member_client(test_db):
    """Authenticated client for a NON-admin user — the case the old single
    'Admin' group mislabelled."""
    async with AsyncSession(test_db) as s:
        s.add(
            User(
                username="member",
                password_hash=cached_password_hash("testpass"),
                is_admin=False,
            )
        )
        await s.commit()

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={settings.session_cookie_name: create_session_cookie("member")},
        headers={"Origin": "http://test"},
    ) as c:
        yield c
    app.dependency_overrides.clear()


async def test_admin_sees_both_rail_groups(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert ">Account</div>" in r.text
    assert ">Administration</div>" in r.text
    # The retired heading must not come back.
    assert ">Admin</div>" not in r.text
    for href in ACCOUNT_LINKS + ADMIN_LINKS:
        assert f'href="{href}"' in r.text, href


async def test_member_sees_account_group_but_no_administration_group(member_client):
    """A non-admin gets the personal-settings group and none of the admin pages —
    the label is now accurate for them, and the admin links stay unrendered."""
    r = await member_client.get("/")
    assert r.status_code == 200
    assert ">Account</div>" in r.text
    assert ">Administration</div>" not in r.text
    for href in ACCOUNT_LINKS:
        assert f'href="{href}"' in r.text, href
    for href in ADMIN_LINKS:
        assert f'href="{href}"' not in r.text, href


async def test_help_is_an_account_item_not_an_admin_one(member_client):
    """Help sat outside the conditional but inside the 'Admin' group. It belongs to
    the Account group, so a member must still reach it."""
    r = await member_client.get("/")
    assert 'href="/help"' in r.text


async def test_dashboard_has_exactly_one_search_input(client):
    """The dashboard carried its own search form submitting to the same place as the
    top-bar box — two inputs, one behaviour. The top bar is the single entry point."""
    r = await client.get("/")
    assert r.text.count('name="q"') == 0, "the in-page search form is gone"
    assert len(re.findall(r'<input[^>]*type="text"', r.text)) == 1


async def test_active_search_renders_a_clear_chip(client, test_db, admin_user):
    """Removing the form removed its Clear button, so the active query still needs a
    visible way out."""
    async with AsyncSession(test_db) as s:
        from app.models import Extension

        s.add(
            Extension(
                user_id=admin_user.id,
                store="chrome",
                extension_id="b" * 32,
                name="Findme",
                publisher="Acme",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
            )
        )
        await s.commit()

    r = await client.get("/?q=Findme")
    assert 'class="chip"' in r.text
    assert "Findme" in r.text


async def test_shell_renders_one_breadcrumb_per_page(client):
    """iceberg.css ships .topbar-crumb/.crumb-* — before this they were dead CSS and
    each page hand-rolled its own crumb (or had none)."""
    for path, leaf in (
        ("/", "Extensions"),
        ("/account", "Alerts &amp; webhooks"),
        ("/account/keys", "API keys"),
        ("/extensions/add", "Add extension"),
        ("/help", "Help"),
        ("/admin/users", "Users"),
    ):
        r = await client.get(path)
        assert r.status_code == 200, path
        assert r.text.count('class="topbar-crumb"') == 1, path
        assert f'<span class="crumb-leaf">{leaf}</span>' in r.text, path


async def test_account_page_has_no_hand_rolled_crumb(client):
    """account.html built its own 'Account / Alerts & webhooks' row in the content
    column; the shell crumb replaces it."""
    r = await client.get("/account")
    assert "<span>Account</span>" not in r.text
