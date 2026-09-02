"""Role-based access control (#33): admin / analyst / auditor.

Acceptance from the issue: an auditor is 403 on every mutating route; an analyst
can triage but cannot manage users or alert destinations. The JSON API is the
enforcement point; the HTML routes redirect (303) and the shell hides controls.
"""

import json
import re
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import CheckConstraint
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import create_session_cookie, require_role, require_role_ui
from app.config import settings
from app.database import get_session
from app.main import app
from app.models import Extension, Role, User
from tests.conftest import cached_password_hash


@asynccontextmanager
async def _client_for(test_db, username: str):
    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={settings.session_cookie_name: create_session_cookie(username)},
        headers={"Origin": "http://test"},
    ) as c:
        yield c
    app.dependency_overrides.clear()


async def _make_user(test_db, username: str, role: str) -> User:
    async with AsyncSession(test_db) as s:
        user = User(username=username, password_hash=cached_password_hash("pw"), role=role)
        s.add(user)
        await s.commit()
        await s.refresh(user)
        return user


async def _make_extension(test_db, owner_id: int) -> int:
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=owner_id,
            store="vscode",
            extension_id="publisher.rbac-test",
            name="RBAC test",
            publisher="Publisher",
            version="1.0.0",
            store_url="https://marketplace.visualstudio.com/items?itemName=publisher.rbac-test",
            risk_score=40,
            heuristic_risk_score=40,
            risk_detail=json.dumps({"total": 40, "risk_level": "medium"}),
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        assert ext.id is not None
        return ext.id


@pytest_asyncio.fixture
async def analyst(test_db) -> User:
    return await _make_user(test_db, "analyst1", "analyst")


@pytest_asyncio.fixture
async def auditor(test_db) -> User:
    return await _make_user(test_db, "auditor1", "auditor")


@pytest_asyncio.fixture
async def analyst_client(test_db, analyst):
    async with _client_for(test_db, analyst.username) as c:
        yield c


@pytest_asyncio.fixture
async def auditor_client(test_db, auditor):
    async with _client_for(test_db, auditor.username) as c:
        yield c


# --------------------------------------------------------------------------- #
# Enum ⇄ schema lockstep
# --------------------------------------------------------------------------- #


def test_role_check_constraint_matches_enum():
    """The ck_user_role CHECK is the DB backstop for ``Role``; drift here means a
    role the app accepts that the schema rejects (or vice versa)."""
    checks = [c for c in User.__table_args__ if isinstance(c, CheckConstraint) and c.name == "ck_user_role"]
    assert len(checks) == 1
    literals = set(re.findall(r"'([a-z]+)'", str(checks[0].sqltext)))
    assert literals == {r.value for r in Role} == {"admin", "analyst", "auditor"}


async def test_schema_rejects_unknown_role(test_db):
    async with AsyncSession(test_db) as s:
        s.add(User(username="bogus", password_hash="x", role="superuser"))
        with pytest.raises(IntegrityError):
            await s.commit()


def test_require_role_needs_at_least_one_role():
    with pytest.raises(ValueError):
        require_role()
    with pytest.raises(ValueError):
        require_role_ui()


def test_is_admin_is_gone_and_default_role_is_analyst():
    """#33 says *replace* the bool: no property keeps the old spelling alive."""
    assert not hasattr(User, "is_admin")
    assert User(username="c").role == Role.ANALYST  # default for locally created users


# --------------------------------------------------------------------------- #
# Auditor: read everything, change nothing
# --------------------------------------------------------------------------- #

_AUDITOR_BLOCKED = [
    ("post", "/api/extensions", {"store": "vscode", "extension_id": "pub.ext"}),
    ("post", "/api/extensions/bulk", {"items": [{"store": "vscode", "extension_id": "pub.ext"}]}),
    ("post", "/api/inventory", {"observations": [{"store": "vscode", "extension_id": "pub.ext", "asset_id": "a"}]}),
    ("delete", "/api/extensions/1", None),
    ("post", "/api/extensions/1/refresh", None),
    ("patch", "/api/extensions/1/watchlist", {"watchlist": False}),
    ("patch", "/api/extensions/1/triage", {"triage_status": "resolved"}),
    ("post", "/api/threatlist", {"entries": [{"store": "vscode", "extension_id": "pub.ext"}]}),
    ("post", "/api/alerts/destinations", {"label": "x", "kind": "webhook", "target": "https://example.com/h"}),
    ("patch", "/api/alerts/destinations/1", {"enabled": False}),
    ("delete", "/api/alerts/destinations/1", None),
    ("post", "/api/alerts/destinations/1/test", None),
    ("post", "/api/alerts/rules", {"destination_id": 1, "event_type": "new_version"}),
    ("patch", "/api/alerts/rules/1", {"enabled": False}),
    ("delete", "/api/alerts/rules/1", None),
    ("get", "/api/users", None),
    ("post", "/api/users", {"username": "x", "password": "longenough"}),
    ("delete", "/api/users/1", None),
    ("get", "/api/proxy/settings", None),
    ("put", "/api/proxy/settings", {"mode": "NONE"}),
    ("post", "/api/proxy/test", {"target": "x"}),
    ("get", "/api/oidc/settings", None),
    ("put", "/api/oidc/settings", {"auth_mode": "both"}),
]


@pytest.mark.parametrize("method, path, body", _AUDITOR_BLOCKED, ids=[f"{m}:{p}" for m, p, _ in _AUDITOR_BLOCKED])
async def test_auditor_is_forbidden_from_every_mutation(auditor_client, method, path, body):
    r = await auditor_client.request(method.upper(), path, json=body)
    assert r.status_code == 403, (path, r.text)
    # The refusal names the required roles, never the caller's own role.
    assert "auditor" not in r.json()["detail"]


async def test_auditor_can_read(auditor_client, test_db, admin_user):
    ext_id = await _make_extension(test_db, admin_user.id)  # someone else's — list is owner-scoped
    for path in ("/api/extensions", "/api/alerts/destinations", "/api/alerts/rules", "/api/alerts/log", "/api/keys"):
        r = await auditor_client.get(path)
        assert r.status_code == 200, path
    # And the trail — the role's purpose (#34).
    r = await auditor_client.get("/api/audit")
    assert r.status_code == 200
    r = await auditor_client.get(f"/api/extensions/{ext_id}")
    assert r.status_code == 404  # owner scoping is unchanged by the role


async def test_auditor_keeps_credential_self_service(auditor_client, test_db, auditor):
    """Read-only for workspace data, not for their own secrets: without this an
    auditor could never rotate a leaked password (there is no admin reset)."""
    r = await auditor_client.post("/api/keys", json={"label": "siem-pull", "readonly": True})
    assert r.status_code == 201
    key_id = r.json()["id"]
    r = await auditor_client.delete(f"/api/keys/{key_id}")
    assert r.status_code == 200
    r = await auditor_client.patch(
        "/api/users/me/password", json={"current_password": "pw", "new_password": "a-new-password"}
    )
    assert r.status_code == 200


async def test_auditor_bearer_key_still_cannot_write(auditor_client, test_db, auditor):
    """An auditor's API key carries the auditor role — a non-readonly key is not a
    privilege escalation path."""
    r = await auditor_client.post("/api/keys", json={"label": "rw", "readonly": False})
    raw = r.json()["raw_key"]
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", headers={"Authorization": f"Bearer {raw}"}
    ) as c:
        r = await c.post("/api/extensions", json={"store": "vscode", "extension_id": "pub.ext"})
        assert r.status_code == 403
        r = await c.get("/api/audit")
        assert r.status_code == 200


# --------------------------------------------------------------------------- #
# Analyst: triage, but no user / destination / settings admin
# --------------------------------------------------------------------------- #


async def test_analyst_can_triage_and_delete_own_extension(analyst_client, test_db, analyst):
    ext_id = await _make_extension(test_db, analyst.id)
    r = await analyst_client.patch(
        f"/api/extensions/{ext_id}/triage", json={"triage_status": "accepted-risk", "risk_override": "allow"}
    )
    assert r.status_code == 200
    assert r.json()["risk_level"] == "suppressed"
    r = await analyst_client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    assert r.status_code == 200
    r = await analyst_client.delete(f"/api/extensions/{ext_id}")
    assert r.status_code == 200


_ANALYST_BLOCKED = [
    ("post", "/api/alerts/destinations", {"label": "x", "kind": "webhook", "target": "https://example.com/h"}),
    ("patch", "/api/alerts/destinations/1", {"enabled": False}),
    ("delete", "/api/alerts/destinations/1", None),
    ("post", "/api/alerts/destinations/1/test", None),
    ("post", "/api/alerts/rules", {"destination_id": 1, "event_type": "new_version"}),
    ("patch", "/api/alerts/rules/1", {"enabled": False}),
    ("delete", "/api/alerts/rules/1", None),
    ("get", "/api/users", None),
    ("post", "/api/users", {"username": "x", "password": "longenough"}),
    ("delete", "/api/users/1", None),
    ("put", "/api/proxy/settings", {"mode": "NONE"}),
    ("post", "/api/proxy/test", {"target": "x"}),
    ("put", "/api/oidc/settings", {"auth_mode": "both"}),
    ("post", "/api/threatlist", {"entries": [{"store": "vscode", "extension_id": "pub.ext"}]}),
    ("get", "/api/audit", None),
]


@pytest.mark.parametrize("method, path, body", _ANALYST_BLOCKED, ids=[f"{m}:{p}" for m, p, _ in _ANALYST_BLOCKED])
async def test_analyst_cannot_administer(analyst_client, method, path, body):
    r = await analyst_client.request(method.upper(), path, json=body)
    assert r.status_code == 403, (path, r.text)


async def test_analyst_keeps_credential_self_service(analyst_client):
    r = await analyst_client.post("/api/keys", json={"label": "k"})
    assert r.status_code == 201


# --------------------------------------------------------------------------- #
# Admin: user management carries the role
# --------------------------------------------------------------------------- #


async def test_admin_creates_users_with_roles(client):
    r = await client.post("/api/users", json={"username": "ro", "password": "longenough", "role": "auditor"})
    assert r.status_code == 201
    assert r.json()["role"] == "auditor"
    r = await client.post("/api/users", json={"username": "adm", "password": "longenough", "role": "admin"})
    assert r.status_code == 201
    assert r.json()["role"] == "admin"
    # Default is analyst; the retired is_admin field is ignored, not honoured.
    r = await client.post("/api/users", json={"username": "legacy", "password": "longenough", "is_admin": True})
    assert r.status_code == 201
    assert r.json()["role"] == "analyst"
    r = await client.post("/api/users", json={"username": "bad", "password": "longenough", "role": "superuser"})
    assert r.status_code == 422
    r = await client.get("/api/users")
    assert {u["username"]: u["role"] for u in r.json()}["testadmin"] == "admin"
    assert all("is_admin" not in u for u in r.json())


# --------------------------------------------------------------------------- #
# HTML shell: redirects + control gating
# --------------------------------------------------------------------------- #


async def test_write_pages_redirect_auditor(auditor_client):
    for path in ("/extensions/add", "/extensions/bulk"):
        r = await auditor_client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/", path


async def test_write_pages_open_for_analyst(analyst_client):
    for path in ("/extensions/add", "/extensions/bulk"):
        r = await analyst_client.get(path)
        assert r.status_code == 200, path


async def test_audit_page_is_admin_or_auditor(client, analyst_client, auditor_client):
    assert (await client.get("/admin/audit")).status_code == 200
    assert (await auditor_client.get("/admin/audit")).status_code == 200
    r = await analyst_client.get("/admin/audit", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


async def test_rail_reflects_role(client, analyst_client, auditor_client):
    admin_html = (await client.get("/")).text
    assert ">Administration</div>" in admin_html
    assert 'href="/admin/audit"' in admin_html and 'href="/extensions/add"' in admin_html
    assert "workspace admin" in admin_html

    analyst_html = (await analyst_client.get("/")).text
    assert ">Administration</div>" not in analyst_html
    assert 'href="/admin/audit"' not in analyst_html
    assert 'href="/extensions/add"' in analyst_html
    assert ">analyst</span>" in analyst_html

    auditor_html = (await auditor_client.get("/")).text
    assert ">Administration</div>" not in auditor_html
    assert ">Audit</div>" in auditor_html and 'href="/admin/audit"' in auditor_html
    assert 'href="/extensions/add"' not in auditor_html
    assert "auditor · read-only" in auditor_html


async def test_detail_page_hides_mutation_controls_from_auditor(auditor_client, client, test_db, auditor, admin_user):
    ext_id = await _make_extension(test_db, auditor.id)
    html = (await auditor_client.get(f"/extensions/{ext_id}")).text
    for control in ("toggleWatchlist", "refreshNow", "deleteExt", "saveTriage"):
        assert control not in html, control
    # The admin still gets them.
    ext_id = await _make_extension(test_db, admin_user.id)
    html = (await client.get(f"/extensions/{ext_id}")).text
    for control in ("toggleWatchlist", "refreshNow", "deleteExt", "saveTriage"):
        assert control in html, control


async def test_account_page_hides_alert_admin_from_analyst(analyst_client, client):
    html = (await analyst_client.get("/account")).text
    assert "New destination" not in html and "New rule" not in html
    assert "Managed by an admin" in html
    assert "New destination" in (await client.get("/account")).text
