import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.main import app as fastapi_app
from app.models import AlertDestination, AlertLog, AlertRule, Extension
from app.notifications import ChangeEvent, detect_changes, fire_alerts
from app.webhooks import WebhookValidationError, send_webhook

# A fixed public IP the webhook resolver is patched to return, so the SSRF-pinning
# send path is exercised deterministically without real DNS. The pinned request
# therefore targets this IP literal (with the original Host header preserved).
_PINNED_IP = "93.184.216.34"


def _patch_resolver(ip: str = _PINNED_IP):
    """Patch DNS resolution in the webhook send path to a fixed public IP."""
    return patch("app.webhooks._resolve_host", new=AsyncMock(return_value=[ip]))


@pytest.fixture(autouse=True)
def _stub_webhook_dns():
    """Keep webhook URL validation independent of real DNS across all tests.

    Tests use example hostnames (e.g. hooks.example.com) that may or may not
    resolve; stubbing the resolver to a fixed public IP makes both validation
    and the IP-pinned send path deterministic. Individual tests can nest their
    own patch (e.g. to a private IP) to override this default.
    """
    with _patch_resolver():
        yield


# ---------------------------------------------------------------------------
# detect_changes unit tests
# ---------------------------------------------------------------------------

def _ext(**kwargs) -> Extension:
    defaults = dict(
        id=1,
        user_id=1,
        store="vscode",
        extension_id="pub.ext",
        name="Test",
        publisher="TestPub",
        version="1.0.0",
        permissions='["storage"]',
        store_url="https://example.com",
        risk_score=10,
        last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(kwargs)
    return Extension(**defaults)


def test_detect_changes_no_events_on_first_fetch():
    old = _ext(last_fetched_at=None, risk_score=None)
    new = _ext(risk_score=60)
    assert detect_changes(old, new) == []


def test_detect_changes_risk_level():
    old = _ext(risk_score=20)  # low
    new = _ext(risk_score=60)  # high
    events = detect_changes(old, new)
    assert any(e.event_type == "risk_level_change" for e in events)
    ev = next(e for e in events if e.event_type == "risk_level_change")
    assert ev.old_value == "low"
    assert ev.new_value == "high"


def test_detect_changes_same_risk_level_no_event():
    old = _ext(risk_score=20)  # low
    new = _ext(risk_score=24)  # still low
    events = detect_changes(old, new)
    assert not any(e.event_type == "risk_level_change" for e in events)


def test_detect_changes_publisher():
    old = _ext(publisher="GoodPub")
    new = _ext(publisher="SuspiciousPub")
    events = detect_changes(old, new)
    assert any(e.event_type == "publisher_change" for e in events)


def test_detect_changes_permissions():
    old = _ext(permissions='["storage"]')
    new = _ext(permissions='["storage", "tabs"]')
    events = detect_changes(old, new)
    assert any(e.event_type == "permission_change" for e in events)


def test_detect_changes_new_version():
    old = _ext(version="1.0.0")
    new = _ext(version="2.0.0")
    events = detect_changes(old, new)
    assert any(e.event_type == "new_version" for e in events)
    ev = next(e for e in events if e.event_type == "new_version")
    assert ev.old_value == "1.0.0"
    assert ev.new_value == "2.0.0"


def test_detect_changes_no_version_change():
    old = _ext(version="1.0.0")
    new = _ext(version="1.0.0")
    events = detect_changes(old, new)
    assert not any(e.event_type == "new_version" for e in events)


# ---------------------------------------------------------------------------
# Alert CRUD tests (via HTTP client)
# ---------------------------------------------------------------------------

async def test_create_destination(client):
    r = await client.post("/api/alerts/destinations", json={
        "label": "Slack #security",
        "target": "https://hooks.example.com/webhook",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["label"] == "Slack #security"
    assert data["enabled"] is True


async def test_list_destinations(client):
    await client.post("/api/alerts/destinations", json={
        "label": "My Hook", "target": "https://hooks.example.com/1"
    })
    r = await client.get("/api/alerts/destinations")
    assert r.status_code == 200
    assert len(r.json()) >= 1


async def test_update_destination(client):
    r = await client.post("/api/alerts/destinations", json={
        "label": "Old Label", "target": "https://hooks.example.com/2"
    })
    dest_id = r.json()["id"]
    r2 = await client.patch(f"/api/alerts/destinations/{dest_id}", json={"label": "New Label", "enabled": False})
    assert r2.status_code == 200
    assert r2.json()["label"] == "New Label"
    assert r2.json()["enabled"] is False


async def test_delete_destination(client):
    r = await client.post("/api/alerts/destinations", json={
        "label": "To Delete", "target": "https://hooks.example.com/3"
    })
    dest_id = r.json()["id"]
    r_del = await client.delete(f"/api/alerts/destinations/{dest_id}")
    assert r_del.status_code == 200
    r_list = await client.get("/api/alerts/destinations")
    assert not any(d["id"] == dest_id for d in r_list.json())


async def test_create_rule(client):
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/r"
    })
    dest_id = r_dest.json()["id"]

    r = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id,
        "event_type": "risk_level_change",
    })
    assert r.status_code == 201
    assert r.json()["event_type"] == "risk_level_change"
    assert r.json()["extension_id"] is None


async def test_create_rule_invalid_event_type(client):
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/bad"
    })
    dest_id = r_dest.json()["id"]
    r = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id,
        "event_type": "invalid_type",
    })
    assert r.status_code == 422


async def test_toggle_rule_enabled(client):
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/toggle"
    })
    dest_id = r_dest.json()["id"]
    r_rule = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id,
        "event_type": "new_version",
    })
    rule_id = r_rule.json()["id"]

    r2 = await client.patch(f"/api/alerts/rules/{rule_id}", json={"enabled": False})
    assert r2.status_code == 200
    assert r2.json()["enabled"] is False


async def test_delete_rule(client):
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/del"
    })
    dest_id = r_dest.json()["id"]
    r_rule = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id,
        "event_type": "publisher_change",
    })
    rule_id = r_rule.json()["id"]

    r_del = await client.delete(f"/api/alerts/rules/{rule_id}")
    assert r_del.status_code == 200
    r_list = await client.get("/api/alerts/rules")
    assert not any(r["id"] == rule_id for r in r_list.json())


# ---------------------------------------------------------------------------
# fire_alerts integration: webhook POST is sent
# ---------------------------------------------------------------------------

@respx.mock
async def test_fire_alerts_posts_webhook(test_db, admin_user):
    """fire_alerts POSTs to the webhook URL when a matching rule exists."""
    webhook_url = "https://hooks.example.com/fire-test"
    # The send path pins to the resolved IP, so respx matches the IP literal URL.
    route = respx.post(f"https://{_PINNED_IP}/fire-test").mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Test", target=webhook_url, enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="test.fire",
            name="Fire Test",
            publisher="TestPub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=60,
            permissions='["storage"]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(
            user_id=admin_user.id,
            destination_id=dest_id,
            event_type="risk_level_change",
            enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext)  # re-load after commit expires the object

        events = [ChangeEvent("risk_level_change", "low", "high")]
        with _patch_resolver():
            async with httpx.AsyncClient() as http:
                await fire_alerts(events, ext, test_db, http)

    assert respx.calls.call_count == 1
    # The original hostname is preserved in the Host header despite IP pinning.
    assert respx.calls[0].request.headers["Host"] == "hooks.example.com"
    sent = json.loads(respx.calls[0].request.content)
    assert sent["event"] == "risk_level_change"
    assert sent["change"]["old"] == "low"
    assert sent["change"]["new"] == "high"


@respx.mock
async def test_fire_alerts_skips_disabled_rule(test_db, admin_user):
    """Disabled rules do not trigger webhook POSTs."""
    webhook_url = "https://hooks.example.com/disabled-test"
    respx.post(webhook_url).mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Test", target=webhook_url, enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="test.disabled",
            name="Disabled Test",
            publisher="TestPub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=60,
            permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(
            user_id=admin_user.id,
            destination_id=dest_id,
            event_type="risk_level_change",
            enabled=False,  # disabled
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "low", "high")]
        async with httpx.AsyncClient() as http:
            await fire_alerts(events, ext, test_db, http)

    assert respx.calls.call_count == 0


@respx.mock
async def test_fire_alerts_extension_scoped_rule(test_db, admin_user):
    """A rule scoped to a specific extension only fires for that extension."""
    webhook_url = "https://hooks.example.com/scoped-test"
    respx.post(webhook_url).mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Test", target=webhook_url, enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext1 = Extension(
            user_id=admin_user.id, store="chrome", extension_id="ext1",
            name="Ext1", publisher="p", version="1.0", store_url="https://example.com",
            risk_score=60, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        ext2 = Extension(
            user_id=admin_user.id, store="chrome", extension_id="ext2",
            name="Ext2", publisher="p", version="1.0", store_url="https://example.com",
            risk_score=60, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext1)
        session.add(ext2)
        await session.commit()
        await session.refresh(ext1)
        await session.refresh(ext2)
        ext1_id = ext1.id

        # Rule scoped to ext1 only
        rule = AlertRule(
            user_id=admin_user.id,
            destination_id=dest_id,
            event_type="new_version",
            extension_id=ext1_id,
            enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext2)

        events = [ChangeEvent("new_version", "1.0", "2.0")]
        async with httpx.AsyncClient() as http:
            # Fire for ext2 — rule should NOT match
            await fire_alerts(events, ext2, test_db, http)

    assert respx.calls.call_count == 0


# ---------------------------------------------------------------------------
# send_webhook SSRF protection (IP pinning at send time)
# ---------------------------------------------------------------------------

@respx.mock
async def test_send_webhook_pins_to_validated_ip():
    """send_webhook connects to the resolved IP while preserving the Host header."""
    route = respx.post(f"https://{_PINNED_IP}/hook").mock(return_value=httpx.Response(200))
    with _patch_resolver():
        async with httpx.AsyncClient() as http:
            resp = await send_webhook(http, "https://feed.example.com/hook", {"x": 1})
    assert resp.status_code == 200
    assert route.called
    assert route.calls[0].request.headers["Host"] == "feed.example.com"


async def test_send_webhook_blocks_rebind_to_private_ip():
    """If the host resolves to a private IP at send time, no request is made."""
    posted = AsyncMock()
    fake_client = MagicMock()
    fake_client.post = posted
    with patch("app.webhooks._resolve_host", new=AsyncMock(return_value=["10.0.0.5"])):
        with pytest.raises(WebhookValidationError):
            await send_webhook(fake_client, "https://rebind.example.com/hook", {"x": 1})
    posted.assert_not_awaited()


# ---------------------------------------------------------------------------
# Alert log endpoint
# ---------------------------------------------------------------------------

async def test_alert_log_endpoint(client, test_db, admin_user):
    """GET /api/alerts/log returns AlertLog rows for the current user."""
    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Log Hook", target="https://hooks.example.com/log", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id, store="chrome", extension_id="log.ext",
            name="Log Ext", publisher="Pub", version="1.0", store_url="https://example.com",
            risk_score=30, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

        rule = AlertRule(
            user_id=admin_user.id, destination_id=dest_id,
            event_type="new_version", enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
        rule_id = rule.id

        log = AlertLog(
            rule_id=rule_id, extension_id=ext_id,
            event_type="new_version",
            detail=json.dumps({"old": "1.0", "new": "2.0"}),
            success=True,
        )
        session.add(log)
        await session.commit()

    r = await client.get("/api/alerts/log")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) >= 1
    row = next(x for x in rows if x["event_type"] == "new_version")
    assert row["ext_name"] == "Log Ext"
    assert row["dest_label"] == "Log Hook"
    assert row["success"] is True


@respx.mock
async def test_fired_alert_appears_in_history(client, test_db, admin_user):
    """End-to-end: a webhook fired by fire_alerts is visible in the alert history.

    Regression guard for the alert pipeline — fire_alerts writes its AlertLog in a
    separate session keyed on user_id, and get_alert_log must surface it.
    """
    respx.post(f"https://{_PINNED_IP}/history").mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="History Hook",
                                target="https://hooks.example.com/history", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id, store="vscode", extension_id="hist.ext",
            name="History Ext", publisher="Pub", version="1.0", store_url="https://example.com",
            risk_score=80, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(user_id=admin_user.id, destination_id=dest_id,
                         event_type="risk_level_change", enabled=True)
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "medium", "critical")]
        with _patch_resolver():
            async with httpx.AsyncClient() as http:
                await fire_alerts(events, ext, test_db, http)

    r = await client.get("/api/alerts/log")
    assert r.status_code == 200
    rows = r.json()
    row = next(x for x in rows if x["event_type"] == "risk_level_change")
    assert row["ext_name"] == "History Ext"
    assert row["dest_label"] == "History Hook"
    assert row["success"] is True


async def test_delete_destination_preserves_history(client, test_db, admin_user):
    """Deleting a destination must not orphan its AlertLog FK (Postgres enforces it)
    and must keep the historical log rows visible in the alert history."""
    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Gone Hook",
                                target="https://hooks.example.com/gone", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id, store="chrome", extension_id="gone.ext",
            name="Gone Ext", publisher="Pub", version="1.0", store_url="https://example.com",
            risk_score=30, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

        rule = AlertRule(user_id=admin_user.id, destination_id=dest_id,
                         event_type="new_version", enabled=True)
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

        # A historical log carrying the destination snapshot FK.
        session.add(AlertLog(
            rule_id=rule.id, destination_id=dest_id, extension_id=ext_id,
            user_id=admin_user.id, event_type="new_version",
            detail=json.dumps({"old": "1.0", "new": "2.0"}), success=True,
        ))
        await session.commit()

    r_del = await client.delete(f"/api/alerts/destinations/{dest_id}")
    assert r_del.status_code == 200

    # The log survives (now with the destination FK severed) and stays in history.
    r = await client.get("/api/alerts/log")
    assert r.status_code == 200
    row = next(x for x in r.json() if x["event_type"] == "new_version")
    assert row["ext_name"] == "Gone Ext"
    assert row["dest_label"] == "—"  # snapshot destination gone → placeholder

    async with AsyncSession(test_db) as session:
        orphaned = (await session.exec(
            select(AlertLog).where(AlertLog.destination_id == dest_id)
        )).all()
        assert orphaned == []  # FK was severed, not left dangling


# ---------------------------------------------------------------------------
# Test webhook destination endpoint
# ---------------------------------------------------------------------------

async def test_test_destination_success(client, test_db, admin_user):
    """POST /api/alerts/destinations/{id}/test returns ok when webhook responds 200."""
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Test Dest", "target": "https://hooks.example.com/test-dest",
    })
    dest_id = r_dest.json()["id"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()  # no-op

    original = fastapi_app.state.http_client
    fastapi_app.state.http_client = AsyncMock()
    fastapi_app.state.http_client.post = AsyncMock(return_value=mock_resp)
    try:
        with _patch_resolver():
            r = await client.post(f"/api/alerts/destinations/{dest_id}/test")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        call_args = fastapi_app.state.http_client.post.call_args
        sent = call_args.kwargs["json"]
        assert sent["event"] == "test"
        assert "extension" in sent
        assert "change" in sent
        assert "risk_score" in sent
    finally:
        fastapi_app.state.http_client = original


async def test_test_destination_failure(client, test_db, admin_user):
    """POST /api/alerts/destinations/{id}/test returns 502 when webhook fails."""
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Fail Dest", "target": "https://hooks.example.com/test-dest-fail",
    })
    dest_id = r_dest.json()["id"]

    original = fastapi_app.state.http_client
    fastapi_app.state.http_client = AsyncMock()
    fastapi_app.state.http_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
    try:
        with _patch_resolver():
            r = await client.post(f"/api/alerts/destinations/{dest_id}/test")
        assert r.status_code == 502
    finally:
        fastapi_app.state.http_client = original


# ---------------------------------------------------------------------------
# fire_alerts edge cases
# ---------------------------------------------------------------------------

@respx.mock
async def test_fire_alerts_logs_webhook_failure(test_db, admin_user):
    """When the webhook returns an error status, an AlertLog row with success=False is committed."""
    webhook_url = "https://hooks.example.com/fail-log-test"
    respx.post(f"https://{_PINNED_IP}/fail-log-test").mock(return_value=httpx.Response(500))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Fail", target=webhook_url, enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id, store="vscode", extension_id="test.faillog",
            name="Fail Log", publisher="Pub", version="1.0.0",
            store_url="https://example.com", risk_score=60, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(
            user_id=admin_user.id, destination_id=dest_id,
            event_type="risk_level_change", enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "low", "high")]
        with _patch_resolver():
            async with httpx.AsyncClient() as http:
                await fire_alerts(events, ext, test_db, http)

    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 1
    assert logs[0].success is False
    assert logs[0].error is not None
    assert logs[0].destination_id is not None


@respx.mock
async def test_fire_alerts_skips_disabled_destination(test_db, admin_user):
    """An enabled rule pointing to a disabled destination fires no webhook and writes no log."""
    webhook_url = "https://hooks.example.com/disabled-dest-test"
    respx.post(webhook_url).mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Disabled", target=webhook_url, enabled=False)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id, store="vscode", extension_id="test.disableddest",
            name="Disabled Dest", publisher="Pub", version="1.0.0",
            store_url="https://example.com", risk_score=60, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(
            user_id=admin_user.id, destination_id=dest_id,
            event_type="risk_level_change", enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "low", "high")]
        async with httpx.AsyncClient() as http:
            await fire_alerts(events, ext, test_db, http)

    assert respx.calls.call_count == 0
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 0


# ---------------------------------------------------------------------------
# Alert log history preservation
# ---------------------------------------------------------------------------

async def test_delete_rule_preserves_alert_logs(client, test_db, admin_user):
    """Deleting a rule orphans its logs (sets rule_id=None) rather than deleting them."""
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/preserve-rule",
    })
    dest_id = r_dest.json()["id"]
    r_rule = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id, "event_type": "new_version",
    })
    rule_id = r_rule.json()["id"]

    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id, store="chrome", extension_id="preserve-rule-ext",
            name="Preserve", publisher="p", version="1.0", store_url="https://example.com",
            risk_score=10, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        session.add(AlertLog(
            rule_id=rule_id, destination_id=dest_id, extension_id=ext.id,
            user_id=admin_user.id, event_type="new_version",
            detail=json.dumps({"old": "1.0", "new": "2.0"}), success=True,
        ))
        await session.commit()

    r_del = await client.delete(f"/api/alerts/rules/{rule_id}")
    assert r_del.status_code == 200

    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 1
    assert logs[0].rule_id is None

    r_log = await client.get("/api/alerts/log")
    assert r_log.status_code == 200
    assert len(r_log.json()) == 1


async def test_delete_destination_preserves_alert_logs(client, test_db, admin_user):
    """Deleting a destination cascades to rules but orphans logs rather than deleting them."""
    r_dest = await client.post("/api/alerts/destinations", json={
        "label": "Hook", "target": "https://hooks.example.com/preserve-dest",
    })
    dest_id = r_dest.json()["id"]
    r_rule = await client.post("/api/alerts/rules", json={
        "destination_id": dest_id, "event_type": "new_version",
    })
    rule_id = r_rule.json()["id"]

    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id, store="chrome", extension_id="preserve-dest-ext",
            name="Preserve", publisher="p", version="1.0", store_url="https://example.com",
            risk_score=10, permissions='[]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        session.add(AlertLog(
            rule_id=rule_id, destination_id=dest_id, extension_id=ext.id,
            user_id=admin_user.id, event_type="new_version",
            detail=json.dumps({"old": "1.0", "new": "2.0"}), success=True,
        ))
        await session.commit()

    r_del = await client.delete(f"/api/alerts/destinations/{dest_id}")
    assert r_del.status_code == 200

    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 1
    assert logs[0].rule_id is None

    r_log = await client.get("/api/alerts/log")
    assert r_log.status_code == 200
    assert len(r_log.json()) == 1
