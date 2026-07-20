import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.alert_queries import get_alert_log
from app.config import settings
from app.fetchers.base import ExtensionMetadata
from app.main import app as fastapi_app
from app.models import AlertDestination, AlertLog, AlertRule, Extension
from app.notifications import ChangeEvent, build_alert_payload, detect_changes, fire_alerts
from app.services import fetch_and_store, fire_pending_alerts
from app.webhooks import WebhookValidationError, send_webhook, validate_webhook_url

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


def test_detect_changes_host_permission_added():
    # Host permissions live in package_analysis, not ext.permissions. Gaining broad
    # host access must still fire permission_change (#60).
    old = _ext(package_analysis=json.dumps({"host_permissions": []}))
    new = _ext(package_analysis=json.dumps({"host_permissions": ["<all_urls>"]}))
    events = detect_changes(old, new)
    ev = next(e for e in events if e.event_type == "permission_change")
    assert "<all_urls>" in ev.new_value
    assert "<all_urls>" not in ev.old_value


def test_detect_changes_host_permission_unchanged_no_event():
    same = json.dumps({"host_permissions": ["https://example.com/*"]})
    old = _ext(package_analysis=same)
    new = _ext(package_analysis=same)
    events = detect_changes(old, new)
    assert not any(e.event_type == "permission_change" for e in events)


def test_detect_changes_malformed_package_analysis_no_crash():
    # Corrupt stored analysis must not raise — treated as no host permissions.
    old = _ext(package_analysis="{not json")
    new = _ext(package_analysis="{not json")
    events = detect_changes(old, new)
    assert not any(e.event_type == "permission_change" for e in events)


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
    r = await client.post(
        "/api/alerts/destinations",
        json={
            "label": "Slack #security",
            "target": "https://hooks.example.com/webhook",
        },
    )
    assert r.status_code == 201
    data = r.json()
    assert data["label"] == "Slack #security"
    assert data["enabled"] is True


@pytest.mark.parametrize(
    "target",
    [
        # Hostname form: previously an unhandled ValueError (500) at the _resolve_host
        # call's .port access (#283).
        "https://hooks.example.com:99999/webhook",
        "https://hooks.example.com:abc/webhook",
        # Bare-IP form: previously returned early WITHOUT touching .port, so the bad
        # destination was stored and every delivery failed at send time (#283).
        "http://8.8.8.8:99999/webhook",
    ],
)
async def test_create_destination_invalid_port_rejected(client, target):
    r = await client.post("/api/alerts/destinations", json={"label": "Bad Port", "target": target})
    assert r.status_code == 422
    assert "port" in r.json()["detail"].lower()
    # Nothing was stored — the bare-IP form used to slip through validation.
    listing = await client.get("/api/alerts/destinations")
    assert all(d["target"] != target for d in listing.json())


async def test_validate_webhook_url_invalid_port_raises_validation_error():
    """Direct unit contract: ValueError from urlparse .port never escapes (#283)."""
    for url in ("https://hooks.example.com:70000/x", "http://8.8.8.8:70000/x", "https://h.example.com:x/y"):
        with pytest.raises(WebhookValidationError):
            await validate_webhook_url(url)


async def test_list_destinations(client):
    await client.post("/api/alerts/destinations", json={"label": "My Hook", "target": "https://hooks.example.com/1"})
    r = await client.get("/api/alerts/destinations")
    assert r.status_code == 200
    assert len(r.json()) >= 1


async def test_update_destination(client):
    r = await client.post(
        "/api/alerts/destinations", json={"label": "Old Label", "target": "https://hooks.example.com/2"}
    )
    dest_id = r.json()["id"]
    r2 = await client.patch(f"/api/alerts/destinations/{dest_id}", json={"label": "New Label", "enabled": False})
    assert r2.status_code == 200
    assert r2.json()["label"] == "New Label"
    assert r2.json()["enabled"] is False


async def test_delete_destination(client):
    r = await client.post(
        "/api/alerts/destinations", json={"label": "To Delete", "target": "https://hooks.example.com/3"}
    )
    dest_id = r.json()["id"]
    r_del = await client.delete(f"/api/alerts/destinations/{dest_id}")
    assert r_del.status_code == 200
    r_list = await client.get("/api/alerts/destinations")
    assert not any(d["id"] == dest_id for d in r_list.json())


async def test_create_rule(client):
    r_dest = await client.post(
        "/api/alerts/destinations", json={"label": "Hook", "target": "https://hooks.example.com/r"}
    )
    dest_id = r_dest.json()["id"]

    r = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "risk_level_change",
        },
    )
    assert r.status_code == 201
    assert r.json()["event_type"] == "risk_level_change"
    assert r.json()["extension_id"] is None


async def test_create_rule_invalid_event_type(client):
    r_dest = await client.post(
        "/api/alerts/destinations", json={"label": "Hook", "target": "https://hooks.example.com/bad"}
    )
    dest_id = r_dest.json()["id"]
    r = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "invalid_type",
        },
    )
    assert r.status_code == 422


async def test_toggle_rule_enabled(client):
    r_dest = await client.post(
        "/api/alerts/destinations", json={"label": "Hook", "target": "https://hooks.example.com/toggle"}
    )
    dest_id = r_dest.json()["id"]
    r_rule = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "new_version",
        },
    )
    rule_id = r_rule.json()["id"]

    r2 = await client.patch(f"/api/alerts/rules/{rule_id}", json={"enabled": False})
    assert r2.status_code == 200
    assert r2.json()["enabled"] is False


async def test_delete_rule(client):
    r_dest = await client.post(
        "/api/alerts/destinations", json={"label": "Hook", "target": "https://hooks.example.com/del"}
    )
    dest_id = r_dest.json()["id"]
    r_rule = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "publisher_change",
        },
    )
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
    respx.post(f"https://{_PINNED_IP}/fire-test").mock(return_value=httpx.Response(200))

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
            permissions="[]",
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
            user_id=admin_user.id,
            store="chrome",
            extension_id="ext1",
            name="Ext1",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
            risk_score=60,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        ext2 = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="ext2",
            name="Ext2",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
            risk_score=60,
            permissions="[]",
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
        dest = AlertDestination(
            user_id=admin_user.id, label="Log Hook", target="https://hooks.example.com/log", enabled=True
        )
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="log.ext",
            name="Log Ext",
            publisher="Pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=30,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

        rule = AlertRule(
            user_id=admin_user.id,
            destination_id=dest_id,
            event_type="new_version",
            enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
        rule_id = rule.id

        log = AlertLog(
            rule_id=rule_id,
            extension_id=ext_id,
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
        dest = AlertDestination(
            user_id=admin_user.id, label="History Hook", target="https://hooks.example.com/history", enabled=True
        )
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="hist.ext",
            name="History Ext",
            publisher="Pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=80,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="risk_level_change", enabled=True)
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
        dest = AlertDestination(
            user_id=admin_user.id, label="Gone Hook", target="https://hooks.example.com/gone", enabled=True
        )
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="gone.ext",
            name="Gone Ext",
            publisher="Pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=30,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

        rule = AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="new_version", enabled=True)
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

        # A historical log carrying the destination snapshot FK.
        session.add(
            AlertLog(
                rule_id=rule.id,
                destination_id=dest_id,
                extension_id=ext_id,
                user_id=admin_user.id,
                event_type="new_version",
                detail=json.dumps({"old": "1.0", "new": "2.0"}),
                success=True,
            )
        )
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
        orphaned = (await session.exec(select(AlertLog).where(AlertLog.destination_id == dest_id))).all()
        assert orphaned == []  # FK was severed, not left dangling


# ---------------------------------------------------------------------------
# Alerts fire AFTER commit, never during fetch_and_store's open transaction
# ---------------------------------------------------------------------------


async def test_fire_pending_alerts_noop_on_empty_events(test_db):
    with patch("app.services.fire_alerts", new=AsyncMock()) as spy:
        await fire_pending_alerts(
            [],
            Extension(
                id=1, user_id=1, store="chrome", extension_id="x", name="x", publisher="p", version="1", store_url="u"
            ),
            test_db,
            MagicMock(),
        )
    spy.assert_not_called()


async def test_fire_pending_alerts_swallows_errors(test_db):
    """A delivery/logging failure must never propagate out of fire_pending_alerts."""
    ext = Extension(
        id=1, user_id=1, store="chrome", extension_id="x", name="x", publisher="p", version="1", store_url="u"
    )
    with patch("app.services.fire_alerts", new=AsyncMock(side_effect=RuntimeError("boom"))):
        await fire_pending_alerts([ChangeEvent("new_version", "1", "2")], ext, test_db, MagicMock())
    # No exception raised → swallowed as designed.


@respx.mock
async def test_alerts_deferred_until_after_commit(test_db, admin_user):
    """fetch_and_store must NOT fire alerts (it holds the write transaction);
    fire_pending_alerts fires afterwards and the AlertLog is recorded.

    Regression for firing alerts while the caller's write transaction was still
    open — fire_alerts opens a second session and must run after the commit.
    """
    respx.post(f"https://{_PINNED_IP}/deferred").mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(
            user_id=admin_user.id, label="Deferred Hook", target="https://hooks.example.com/deferred", enabled=True
        )
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="defer.ext",
            name="Defer Ext",
            publisher="Pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=20,
            permissions='["storage"]',
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

        session.add(AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="new_version", enabled=True))
        await session.commit()

    # Fetcher returns a new version → triggers a new_version change event.
    meta = ExtensionMetadata(
        name="Defer Ext",
        publisher="Pub",
        description=None,
        version="2.0.0",
        install_count=None,
        last_updated=None,
        store_url="https://example.com",
        publisher_verified=True,
    )

    async with httpx.AsyncClient() as http:
        with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
            MockFetcher.return_value.fetch = AsyncMock(return_value=(meta, None))
            with patch("app.services.fire_alerts", new=AsyncMock()) as spy_fire:
                async with AsyncSession(test_db) as session:
                    ext = await session.get(Extension, ext_id)
                    ext, events = await fetch_and_store(ext, session, http)
                    # Alerts must NOT be fired while the write transaction is open.
                    spy_fire.assert_not_called()
                    assert any(e.event_type == "new_version" for e in events)
                    await session.commit()

        # After the commit releases the lock, fire for real and confirm it lands.
        with _patch_resolver():
            async with AsyncSession(test_db) as session:
                ext = await session.get(Extension, ext_id)
                await fire_pending_alerts(events, ext, test_db, http)

    async with AsyncSession(test_db) as session:
        logs = await get_alert_log(admin_user.id, session)
    assert any(row["event_type"] == "new_version" and row["success"] for row in logs)


# ---------------------------------------------------------------------------
# Test webhook destination endpoint
# ---------------------------------------------------------------------------


async def test_test_destination_success(client, test_db, admin_user):
    """POST /api/alerts/destinations/{id}/test returns ok when webhook responds 200."""
    r_dest = await client.post(
        "/api/alerts/destinations",
        json={
            "label": "Test Dest",
            "target": "https://hooks.example.com/test-dest",
        },
    )
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
    r_dest = await client.post(
        "/api/alerts/destinations",
        json={
            "label": "Fail Dest",
            "target": "https://hooks.example.com/test-dest-fail",
        },
    )
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
            user_id=admin_user.id,
            store="vscode",
            extension_id="test.faillog",
            name="Fail Log",
            publisher="Pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=60,
            permissions="[]",
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


async def test_fire_alerts_persisted_error_is_scrubbed(test_db, admin_user):
    # AlertLog.error is returned by GET /api/alerts/log and rendered in the UI; a
    # delivery failure through the outbound proxy can echo the credential-injected
    # proxy URL in the exception text, so it must pass proxy.scrub first (#228).
    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Hook", target="https://hooks.example.com/w", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        # Capture before the next commit re-expires dest's attributes: an expired
        # attribute access lazy-loads synchronously → MissingGreenlet under asyncpg.
        dest_id = dest.id

        ext = _ext(id=None, user_id=admin_user.id)
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="new_version", enabled=True)
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("new_version", "1.0.0", "2.0.0")]
        leaky = httpx.ProxyError("CONNECT via http://bob:hunter2@proxy.corp:3128 refused")
        # Patch the shared pinned-request core the webhook sender delivers through, so
        # the failure surfaces exactly as a real proxied delivery would (#37 moved the
        # send seam from notifications.send_webhook into the sender dispatch).
        with patch("app.senders.http.send_pinned_request", new=AsyncMock(side_effect=leaky)):
            async with httpx.AsyncClient() as http:
                await fire_alerts(events, ext, test_db, http)

    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 1
    assert logs[0].success is False
    assert "hunter2" not in logs[0].error
    assert "bob" not in logs[0].error
    assert "proxy.corp" in logs[0].error  # only the userinfo is redacted


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
            user_id=admin_user.id,
            store="vscode",
            extension_id="test.disableddest",
            name="Disabled Dest",
            publisher="Pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=60,
            permissions="[]",
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
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "low", "high")]
        async with httpx.AsyncClient() as http:
            await fire_alerts(events, ext, test_db, http)

    assert respx.calls.call_count == 0
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
    assert len(logs) == 0


@respx.mock
async def test_fire_alerts_delivers_all_same_type_events(test_db, admin_user):
    """#144: two events of the SAME type in the pending list are BOTH delivered + logged.

    The #109 merge can leave several events of one type in the marker — e.g. a
    new_version 1.0→1.1 whose delivery failed, then a 1.1→1.2 the next cycle.
    fire_alerts used to collapse events to one per type (dict last-wins), so only
    1.1→1.2 was POSTed/logged and fire_pending_alerts then cleared the whole marker,
    losing 1.0→1.1 with no AlertLog. Every event must reach its matching rule.
    """
    webhook_url = "https://hooks.example.com/all-events"
    respx.post(f"https://{_PINNED_IP}/all-events").mock(return_value=httpx.Response(200))

    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="Dest", target=webhook_url, enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id

        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="test.allevents",
            name="All Events",
            publisher="Pub",
            version="1.2",
            store_url="https://example.com",
            risk_score=60,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        rule = AlertRule(
            user_id=admin_user.id,
            destination_id=dest_id,
            event_type="new_version",
            enabled=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(ext)

        # Two same-type events, oldest first — exactly what the merge stages.
        events = [
            ChangeEvent("new_version", "1.0", "1.1"),
            ChangeEvent("new_version", "1.1", "1.2"),
        ]
        async with httpx.AsyncClient() as http:
            await fire_alerts(events, ext, test_db, http)

    # Both events were POSTed (not collapsed to the latest), in order.
    assert respx.calls.call_count == 2
    posted = [json.loads(c.request.content)["change"] for c in respx.calls]
    assert posted == [{"old": "1.0", "new": "1.1"}, {"old": "1.1", "new": "1.2"}]

    # And both are recorded in the alert log.
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog).where(AlertLog.extension_id == ext.id))).all()
    assert len(logs) == 2
    details = sorted(json.loads(log.detail)["new"] for log in logs)
    assert details == ["1.1", "1.2"]


# ---------------------------------------------------------------------------
# Alert log history preservation
# ---------------------------------------------------------------------------


async def test_delete_rule_preserves_alert_logs(client, test_db, admin_user):
    """Deleting a rule orphans its logs (sets rule_id=None) rather than deleting them."""
    r_dest = await client.post(
        "/api/alerts/destinations",
        json={
            "label": "Hook",
            "target": "https://hooks.example.com/preserve-rule",
        },
    )
    dest_id = r_dest.json()["id"]
    r_rule = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "new_version",
        },
    )
    rule_id = r_rule.json()["id"]

    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="preserve-rule-ext",
            name="Preserve",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
            risk_score=10,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        session.add(
            AlertLog(
                rule_id=rule_id,
                destination_id=dest_id,
                extension_id=ext.id,
                user_id=admin_user.id,
                event_type="new_version",
                detail=json.dumps({"old": "1.0", "new": "2.0"}),
                success=True,
            )
        )
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
    r_dest = await client.post(
        "/api/alerts/destinations",
        json={
            "label": "Hook",
            "target": "https://hooks.example.com/preserve-dest",
        },
    )
    dest_id = r_dest.json()["id"]
    r_rule = await client.post(
        "/api/alerts/rules",
        json={
            "destination_id": dest_id,
            "event_type": "new_version",
        },
    )
    rule_id = r_rule.json()["id"]

    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="preserve-dest-ext",
            name="Preserve",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
            risk_score=10,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        session.add(
            AlertLog(
                rule_id=rule_id,
                destination_id=dest_id,
                extension_id=ext.id,
                user_id=admin_user.id,
                event_type="new_version",
                detail=json.dumps({"old": "1.0", "new": "2.0"}),
                success=True,
            )
        )
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


# ---------------------------------------------------------------------------
# build_alert_payload — the single source of the webhook shape (#168)
# ---------------------------------------------------------------------------


def test_build_alert_payload_shape():
    payload = build_alert_payload(
        text="hello",
        event="risk_level_change",
        ext_id=7,
        name="Ext",
        store="chrome",
        store_url="https://store/ext",
        old="low",
        new="high",
        risk_score=62,
    )
    assert payload == {
        "text": "hello",
        "event": "risk_level_change",
        "extension": {"id": 7, "name": "Ext", "store": "chrome", "store_url": "https://store/ext"},
        "change": {"old": "low", "new": "high"},
        "risk_score": 62,
    }


def test_build_alert_payload_url_only_when_base_url_set(monkeypatch):
    monkeypatch.setattr(settings, "app_base_url", "")
    no_url = build_alert_payload(
        text="t", event="test", ext_id=3, name="E", store="edge", store_url="u", old=1, new=2, risk_score=0
    )
    assert "iceberg_ebs_url" not in no_url["extension"]

    monkeypatch.setattr(settings, "app_base_url", "https://ebs.example.com/")
    with_url = build_alert_payload(
        text="t", event="test", ext_id=3, name="E", store="edge", store_url="u", old=1, new=2, risk_score=0
    )
    # Trailing slash on the base is stripped; the id is interpolated.
    assert with_url["extension"]["iceberg_ebs_url"] == "https://ebs.example.com/extensions/3"


# ---------------------------------------------------------------------------
# Multi-kind destinations (#37)
# ---------------------------------------------------------------------------

_DEST_SECRET_ENV = "ICEBERG_EBS_DEST_SECRET_JIRA_TOKEN"


async def test_destination_kinds_endpoint(client):
    r = await client.get("/api/alerts/destination-kinds")
    assert r.status_code == 200
    kinds = {d["kind"]: d for d in r.json()}
    assert {"webhook", "slack", "teams", "email", "jira", "servicenow"} <= set(kinds)
    # Email is unavailable in tests (no SMTP configured) and advertises why.
    assert kinds["email"]["available"] is False
    assert kinds["email"]["unavailable_reason"]


async def test_create_slack_destination(client):
    r = await client.post(
        "/api/alerts/destinations",
        json={"label": "Slack", "kind": "slack", "target": "https://hooks.slack.com/services/T/B/x"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["kind"] == "slack"
    assert data["config"] == {}


async def test_create_destination_defaults_to_webhook(client):
    """An existing caller that omits kind still creates a webhook destination."""
    r = await client.post(
        "/api/alerts/destinations", json={"label": "Legacy", "target": "https://hooks.example.com/legacy"}
    )
    assert r.status_code == 201
    assert r.json()["kind"] == "webhook"


async def test_create_destination_unknown_kind_rejected(client):
    r = await client.post(
        "/api/alerts/destinations",
        json={"label": "Nope", "kind": "carrier_pigeon", "target": "https://hooks.example.com/x"},
    )
    assert r.status_code == 422
    assert "kind" in r.json()["detail"].lower()


async def test_create_email_destination_refused_when_smtp_unconfigured(client):
    r = await client.post(
        "/api/alerts/destinations",
        json={"label": "Mail", "kind": "email", "target": "ops@example.com"},
    )
    assert r.status_code == 422
    assert "smtp" in r.json()["detail"].lower()


async def test_create_jira_destination_requires_secret(client, monkeypatch):
    body = {
        "label": "Jira",
        "kind": "jira",
        "target": "https://x.atlassian.net",
        "config": {"project_key": "SEC", "account_email": "bot@example.com", "secret_ref": "JIRA_TOKEN"},
    }
    # No env secret yet → 422.
    r = await client.post("/api/alerts/destinations", json=body)
    assert r.status_code == 422

    monkeypatch.setenv(_DEST_SECRET_ENV, "tok")
    r2 = await client.post("/api/alerts/destinations", json=body)
    assert r2.status_code == 201
    # Config (non-secret) round-trips; the secret itself is never stored.
    assert r2.json()["config"]["project_key"] == "SEC"
    assert "tok" not in str(r2.json())


async def test_patch_kind_change_revalidates_resulting_state(client):
    """Changing kind alone must revalidate the existing target/config under the new
    adapter (the #217 resulting-state rule) — a webhook target is not a valid Jira
    destination without project/secret config."""
    r = await client.post("/api/alerts/destinations", json={"label": "W", "target": "https://hooks.example.com/w"})
    dest_id = r.json()["id"]
    r2 = await client.patch(f"/api/alerts/destinations/{dest_id}", json={"kind": "jira"})
    assert r2.status_code == 422


@respx.mock
async def test_fire_alerts_delivers_slack_and_jira(test_db, admin_user, monkeypatch):
    """Acceptance (#37): one fired rule-set with a Slack AND a Jira destination
    delivers to both, and AlertLog records both."""
    monkeypatch.setenv(_DEST_SECRET_ENV, "tok")
    slack_route = respx.post(f"https://{_PINNED_IP}/slack").mock(return_value=httpx.Response(200))
    jira_route = respx.post(f"https://{_PINNED_IP}/rest/api/3/issue").mock(return_value=httpx.Response(201))

    async with AsyncSession(test_db) as session:
        slack = AlertDestination(
            user_id=admin_user.id, label="Slack", kind="slack", target="https://hooks.slack.com/slack", enabled=True
        )
        jira = AlertDestination(
            user_id=admin_user.id,
            label="Jira",
            kind="jira",
            target="https://x.atlassian.net",
            config=json.dumps({"project_key": "SEC", "account_email": "bot@example.com", "secret_ref": "JIRA_TOKEN"}),
            enabled=True,
        )
        session.add(slack)
        session.add(jira)
        await session.commit()
        await session.refresh(slack)
        await session.refresh(jira)
        slack_id, jira_id = slack.id, jira.id

        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="multi.kind",
            name="Multi Kind",
            publisher="Pub",
            version="1.0",
            store_url="https://example.com",
            risk_score=80,
            permissions="[]",
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        session.add(
            AlertRule(user_id=admin_user.id, destination_id=slack_id, event_type="risk_level_change", enabled=True)
        )
        session.add(
            AlertRule(user_id=admin_user.id, destination_id=jira_id, event_type="risk_level_change", enabled=True)
        )
        await session.commit()
        await session.refresh(ext)

        events = [ChangeEvent("risk_level_change", "medium", "critical")]
        with _patch_resolver():
            async with httpx.AsyncClient() as http:
                await fire_alerts(events, ext, test_db, http)

    assert slack_route.called and jira_route.called
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog).where(AlertLog.extension_id == ext.id))).all()
    assert len(logs) == 2
    assert {log.destination_id for log in logs} == {slack_id, jira_id}
    assert all(log.success for log in logs)


async def test_test_slack_destination(client, test_db, admin_user):
    """The destination-test endpoint dispatches through the kind's sender (#168)."""
    r_dest = await client.post(
        "/api/alerts/destinations",
        json={"label": "Slack Test", "kind": "slack", "target": "https://hooks.slack.com/services/x"},
    )
    dest_id = r_dest.json()["id"]

    captured = {}

    async def fake_post(url, **kwargs):
        captured["json"] = kwargs["json"]
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        return resp

    original = fastapi_app.state.http_client
    fastapi_app.state.http_client = AsyncMock()
    fastapi_app.state.http_client.post = AsyncMock(side_effect=fake_post)
    try:
        with _patch_resolver():
            r = await client.post(f"/api/alerts/destinations/{dest_id}/test")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        # Slack shape, not the generic webhook payload.
        assert "blocks" in captured["json"]
    finally:
        fastapi_app.state.http_client = original


def test_test_and_real_alert_payloads_share_shape():
    """The point of #168: the destination-test payload and a real alert payload are
    built by the same function, so their on-the-wire shape can't drift apart."""
    real = build_alert_payload(
        text="real",
        event="new_version",
        ext_id=42,
        name="Real Ext",
        store="vscode",
        store_url="https://store/real",
        old="1.0",
        new="1.1",
        risk_score=80,
    )
    test = build_alert_payload(
        text='IcebergEBS test alert from destination "D"',
        event="test",
        ext_id=0,
        name="Example Extension",
        store="chrome",
        store_url="https://chromewebstore.google.com/detail/example",
        old="low",
        new="high",
        risk_score=62,
    )
    assert real.keys() == test.keys()
    assert real["extension"].keys() == test["extension"].keys()
    assert real["change"].keys() == test["change"].keys()
