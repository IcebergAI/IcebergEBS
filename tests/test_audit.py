"""Audit log of mutating actions (#34).

Two invariants, both directions:
  * every mutation writes an ``AuditLog`` row in the SAME transaction (a rejected
    or rolled-back request writes nothing);
  * every non-GET route in ``app/routes`` either records, or is on an explicit,
    justified allowlist — enforced statically over the route source so a new
    mutating endpoint cannot ship un-audited.
"""

import ast
import json
import pathlib
from unittest.mock import AsyncMock, patch

import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import AuditLog, Extension, User
from tests.test_api import _fake_metadata, _fake_vsix
from tests.test_rbac import _client_for, _make_extension, _make_user


async def _rows(test_db, action: str | None = None) -> list[AuditLog]:
    async with AsyncSession(test_db) as s:
        stmt = select(AuditLog).order_by(AuditLog.id)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        return list((await s.exec(stmt)).all())


# --------------------------------------------------------------------------- #
# Representative actions (the issue's acceptance: "verify in DB")
# --------------------------------------------------------------------------- #


async def test_extension_create_is_audited_with_the_new_id(client, test_db):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={"store": "vscode", "extension_id": "publisher.test"})
    assert r.status_code == 201
    (row,) = await _rows(test_db, "extension.create")
    assert row.actor == "testadmin" and row.actor_id is not None
    assert row.target_type == "extension" and row.target_id == str(r.json()["id"])
    assert row.detail_dict() == {
        "store": "vscode",
        "extension_id": "publisher.test",
        "via": "add",
        "scored_inline": True,
    }
    assert row.ip is not None  # the ASGI test transport still reports a peer


async def test_failed_first_fetch_records_create_then_discard(client, test_db):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=RuntimeError("boom in inspector"))
        with pytest.raises(RuntimeError):
            await client.post("/api/extensions", json={"store": "vscode", "extension_id": "publisher.test"})
    actions = [r.action for r in await _rows(test_db)]
    assert actions == ["extension.create", "extension.discard"]
    async with AsyncSession(test_db) as s:
        assert (await s.exec(select(Extension))).first() is None  # the placeholder really is gone


async def test_triage_watchlist_delete_are_audited(client, test_db, admin_user):
    ext_id = await _make_extension(test_db, admin_user.id)
    r = await client.patch(
        f"/api/extensions/{ext_id}/triage",
        json={"triage_status": "accepted-risk", "risk_override": "allow", "triage_notes": "  pilot  "},
    )
    assert r.status_code == 200
    (triage,) = await _rows(test_db, "extension.triage")
    assert triage.target_id == str(ext_id)
    assert triage.detail_dict() == {
        "triage_status": "accepted-risk",
        "risk_override": "allow",
        "triage_notes": "pilot",  # the RESULTING value (stripped), not the raw input
        "risk_score": 0,
        "risk_level": "suppressed",
    }

    await client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    (wl,) = await _rows(test_db, "extension.watchlist")
    assert wl.detail_dict() == {"watchlist": False}

    await client.delete(f"/api/extensions/{ext_id}")
    (dl,) = await _rows(test_db, "extension.delete")
    assert dl.detail_dict()["extension_id"] == "publisher.rbac-test"
    # The trail outlives the extension row it describes.
    async with AsyncSession(test_db) as s:
        assert await s.get(Extension, ext_id) is None


async def test_rejected_requests_write_nothing(client, test_db, admin_user):
    """The same-transaction invariant from the other side: a 422 (validated before
    the row is staged) and a 404 (not the caller's row) leave no trail entry."""
    ext_id = await _make_extension(test_db, admin_user.id)
    assert (await client.patch(f"/api/extensions/{ext_id}/triage", json={})).status_code == 422
    assert (await client.patch("/api/extensions/999999/watchlist", json={"watchlist": True})).status_code == 404
    assert (
        await client.post("/api/users", json={"username": "testadmin", "password": "longenough"})
    ).status_code == 409
    assert (await client.put("/api/proxy/settings", json={"mode": "bogus"})).status_code == 422
    assert await _rows(test_db) == []


async def test_destination_and_rule_crud_are_audited(client, test_db):
    r = await client.post(
        "/api/alerts/destinations",
        json={"label": "hook", "kind": "webhook", "target": "https://example.com/hook", "config": {}},
    )
    assert r.status_code == 201, r.text
    dest_id = r.json()["id"]
    r = await client.post("/api/alerts/rules", json={"destination_id": dest_id, "event_type": "new_version"})
    assert r.status_code == 201, r.text
    rule_id = r.json()["id"]
    await client.patch(f"/api/alerts/rules/{rule_id}", json={"enabled": False})
    await client.patch(f"/api/alerts/destinations/{dest_id}", json={"label": "renamed"})
    await client.delete(f"/api/alerts/rules/{rule_id}")
    await client.delete(f"/api/alerts/destinations/{dest_id}")
    rows = await _rows(test_db)
    assert [(r.action, r.target_id) for r in rows] == [
        ("destination.create", str(dest_id)),
        ("rule.create", str(rule_id)),
        ("rule.update", str(rule_id)),
        ("destination.update", str(dest_id)),
        ("rule.delete", str(rule_id)),
        ("destination.delete", str(dest_id)),
    ]
    assert rows[3].detail_dict()["fields"] == ["label"]
    assert rows[3].detail_dict()["label"] == "renamed"


async def test_api_key_lifecycle_never_records_the_secret(client, test_db):
    r = await client.post("/api/keys", json={"label": "ci", "readonly": True})
    raw = r.json()["raw_key"]
    await client.delete(f"/api/keys/{r.json()['id']}")
    create, revoke = await _rows(test_db)
    assert (create.action, revoke.action) == ("apikey.create", "apikey.revoke")
    for row in (create, revoke):
        assert raw not in (row.detail or "")
        assert row.detail_dict()["key_prefix"] == raw[:12]
        assert row.detail_dict()["key_suffix"] == raw[-4:]
    assert create.detail_dict()["readonly"] is True


async def test_user_lifecycle_is_audited_and_actor_survives_deletion(client, test_db):
    r = await client.post("/api/users", json={"username": "temp", "password": "longenough", "role": "analyst"})
    temp_id = r.json()["id"]
    # The new user acts …
    async with _client_for(test_db, "temp") as temp_client:
        rk = await temp_client.post("/api/keys", json={"label": "mine"})
        assert rk.status_code == 201
        rp = await temp_client.patch(
            "/api/users/me/password", json={"current_password": "longenough", "new_password": "another-long-one"}
        )
        assert rp.status_code == 200
    # … then the admin deletes them.
    assert (await client.delete(f"/api/users/{temp_id}")).status_code == 200

    rows = await _rows(test_db)
    assert [r.action for r in rows] == ["user.create", "apikey.create", "user.password_change", "user.delete"]
    create, key, pw, delete = rows
    assert create.detail_dict() == {"username": "temp", "role": "analyst", "email": None}
    assert pw.detail is None  # the event only — nothing about the password
    assert pw.target_id == str(temp_id)
    # SET NULL on the FK, username snapshot kept: the trail still says who.
    for row in (key, pw):
        assert row.actor == "temp" and row.actor_id is None
    assert delete.detail_dict()["username"] == "temp"


async def test_settings_updates_record_field_names_not_values(client, test_db):
    # Credentials are env-only (#216) so a URL can't carry them here — but the URL
    # itself still names internal infrastructure and must not reach the trail.
    r = await client.put(
        "/api/proxy/settings", json={"mode": "EXPLICIT", "proxy_url": "http://egress.corp.internal:3128"}
    )
    assert r.status_code == 200, r.text
    (row,) = await _rows(test_db, "settings.proxy.update")
    assert row.target_id == "proxy"
    assert row.detail_dict() == {"fields": ["mode", "proxy_url"], "mode": "EXPLICIT"}
    assert "egress.corp.internal" not in (row.detail or "")

    r = await client.put("/api/oidc/settings", json={"auth_mode": "local"})
    assert r.status_code == 200, r.text
    (row,) = await _rows(test_db, "settings.oidc.update")
    assert row.detail_dict() == {"fields": ["auth_mode"], "auth_mode": "local"}

    # A no-op save (same values again) is not a change and writes nothing.
    await client.put("/api/oidc/settings", json={"auth_mode": "local"})
    assert len(await _rows(test_db, "settings.oidc.update")) == 1


async def test_threatlist_ingest_is_audited(client, test_db, admin_user):
    await _make_extension(test_db, admin_user.id)
    r = await client.post(
        "/api/threatlist",
        json={"source": "feed-x", "entries": [{"store": "vscode", "extension_id": "publisher.rbac-test"}]},
    )
    assert r.status_code == 202, r.text
    (row,) = await _rows(test_db, "threatlist.ingest")
    assert row.detail_dict() == {"entries": 1, "source": "feed-x", "matched_extensions": 1}


async def test_oidc_provisioning_and_role_sync_are_audited(session, test_db):
    from app.oidc.service import provision_oidc_user
    from tests.test_oidc import _cfg, _identity

    cfg = _cfg(role_map={"ebs-admins": "admin"})
    user, created = await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=[]))
    assert created
    await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=["ebs-admins"]))
    rows = await _rows(test_db)
    assert [r.action for r in rows] == ["user.provision", "user.role_sync"]
    assert rows[0].actor == user.username and rows[0].detail_dict()["role"] == "analyst"
    assert rows[1].detail_dict() == {"previous": "analyst", "role": "admin", "provider": "authentik", "via": "oidc"}


# --------------------------------------------------------------------------- #
# Read side
# --------------------------------------------------------------------------- #


async def test_audit_api_is_newest_first_filterable_and_role_gated(client, test_db, admin_user, anon_client):
    ext_id = await _make_extension(test_db, admin_user.id)
    await client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    await client.post("/api/keys", json={"label": "k"})
    r = await client.get("/api/audit")
    assert r.status_code == 200
    assert [e["action"] for e in r.json()] == ["apikey.create", "extension.watchlist"]
    assert r.json()[1]["detail"] == {"watchlist": False}
    r = await client.get("/api/audit", params={"target_type": "extension", "target_id": ext_id})
    assert [e["action"] for e in r.json()] == ["extension.watchlist"]
    r = await client.get("/api/audit", params={"actor": "nobody"})
    assert r.json() == []
    assert (await client.get("/api/audit", params={"limit": 0})).status_code == 422
    assert (await anon_client.get("/api/audit")).status_code == 401

    await _make_user(test_db, "reader", "auditor")
    async with _client_for(test_db, "reader") as reader:
        assert len((await reader.get("/api/audit")).json()) == 2
    await _make_user(test_db, "worker", "analyst")
    async with _client_for(test_db, "worker") as worker:
        assert (await worker.get("/api/audit")).status_code == 403


async def test_audit_page_renders_entries_and_filters(client, test_db, admin_user):
    ext_id = await _make_extension(test_db, admin_user.id)
    await client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    html = (await client.get("/admin/audit")).text
    assert "extension.watchlist" in html and f"extension #{ext_id}" in html and "testadmin" in html
    assert (await client.get("/admin/audit", params={"action": "nothing.here"})).text.count("No audit entries") == 1


# --------------------------------------------------------------------------- #
# Static guard: no un-audited mutating route
# --------------------------------------------------------------------------- #

_ROUTES = pathlib.Path(__file__).resolve().parents[1] / "app" / "routes"
_MUTATING = {"post", "put", "patch", "delete"}
# Helpers that record on the caller's behalf — a route that calls one is covered.
_AUDITING_HELPERS = {"_enroll_extension"}
# Routes that legitimately write no trail row, each with the reason.
# (The OIDC login/callback are GETs — their provisioning + role sync are audited
# inside oidc/service.py as user.provision / user.role_sync, covered above.)
_ALLOWLIST = {
    "login_post": "authentication event, not a workspace mutation (session audit is a follow-up)",
    "logout": "authentication event, not a workspace mutation",
}


def _mutating_routes() -> list[tuple[str, ast.AsyncFunctionDef | ast.FunctionDef, str]]:
    found = []
    for path in sorted(_ROUTES.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in _MUTATING
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "router"
                ):
                    found.append((path.name, node, ast.get_source_segment(path.read_text(), node) or ""))
    return found


def _calls(node: ast.AST) -> set[str]:
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "audit":
                names.add(f"audit.{f.attr}")
            elif isinstance(f, ast.Name):
                names.add(f.id)
    return names


def test_every_mutating_route_is_audited_or_allowlisted():
    routes = _mutating_routes()
    assert len(routes) >= 25, "route discovery broke — expected the full mutating surface"
    missing = []
    for file, node, _src in routes:
        calls = _calls(node)
        if {"audit.record", "audit.build"} & calls or _AUDITING_HELPERS & calls or node.name in _ALLOWLIST:
            continue
        missing.append(f"{file}:{node.name}")
    assert missing == [], f"mutating routes without an audit.record/build call: {missing}"
    # The allowlist must not rot into covering routes that no longer exist.
    names = {node.name for _, node, _ in routes}
    assert set(_ALLOWLIST) <= names, set(_ALLOWLIST) - names


def test_audit_detail_never_carries_a_secret_shaped_key():
    """Every recorded detail dict is built from literal keys in the routes; none of
    them may be a credential field. Grep-level, on purpose: it fails at review time,
    not after a secret has landed in the trail."""
    forbidden = {"password", "password_hash", "raw_key", "key_hash", "client_secret", "proxy_url", "secret"}
    offenders = []
    for path in sorted(_ROUTES.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {
                    "record",
                    "build",
                }
            ):
                if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "audit"):
                    continue
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Dict):
                        for key in sub.keys:
                            if isinstance(key, ast.Constant) and key.value in forbidden:
                                offenders.append(f"{path.name}:{node.lineno}:{key.value}")
    assert offenders == []


def test_audit_detail_roundtrips_json():
    row = AuditLog(actor="a", action="x.y", target_type="x", detail=json.dumps({"k": 1}))
    assert row.detail_dict() == {"k": 1}
    assert AuditLog(actor="a", action="x.y", target_type="x", detail="not json").detail_dict() == {}
    assert AuditLog(actor="a", action="x.y", target_type="x").detail_dict() == {}
    assert User(username="u").role == "analyst"
