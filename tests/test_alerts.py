import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import AlertDestination, AlertRule, Extension
from app.notifications import ChangeEvent, detect_changes, fire_alerts


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
        async with httpx.AsyncClient() as http:
            await fire_alerts(events, ext, session, http)

    assert respx.calls.call_count == 1
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
            await fire_alerts(events, ext, session, http)

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
            await fire_alerts(events, ext2, session, http)

    assert respx.calls.call_count == 0
