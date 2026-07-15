"""Graceful shutdown / recoverable alerts (#109).

A shutdown landing between a committed state change and its webhook delivery must not
silently drop the alert: fetch_and_store stages the pending events in the same commit,
and recover_pending_alerts re-fires them on the next startup/cycle.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import respx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import ExtensionMetadata
from app.models import AlertDestination, AlertLog, AlertRule, Extension
from app.services import fetch_and_store, recover_pending_alerts

_PINNED_IP = "93.184.216.34"
_ROOT = Path(__file__).resolve().parent.parent


def _patch_resolver(ip: str = _PINNED_IP):
    return patch("app.webhooks._resolve_host", new=AsyncMock(return_value=[ip]))


async def test_fetch_and_store_stages_pending_marker(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.marker",
            name="M",
            publisher="pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=10,
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),  # not first fetch
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        meta = ExtensionMetadata(
            name="M", publisher="pub", version="2.0.0", store_url="https://example.com"
        )  # version bump → new_version event
        with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
            MockFetcher.return_value.fetch = AsyncMock(return_value=(meta, None))
            ext, events = await fetch_and_store(ext, session, httpx.AsyncClient())
        # The pending events are staged on the record so they commit atomically.
        assert events
        staged = json.loads(ext.pending_alert_events)
        assert any(e["event_type"] == "new_version" for e in staged)


async def test_recover_clears_marker_when_no_matching_rules(test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.norules",
            name="N",
            publisher="pub",
            version="2.0.0",
            store_url="https://example.com",
            risk_score=10,
            pending_alert_events=json.dumps([{"event_type": "new_version", "old_value": "1.0", "new_value": "2.0"}]),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)  # reload expired PK before reading it outside the session
        ext_id = ext.id

    async with httpx.AsyncClient() as http:
        await recover_pending_alerts(test_db, http)

    async with AsyncSession(test_db) as session:
        refreshed = await session.get(Extension, ext_id)
        # No rules → nothing to deliver, but the marker must not linger and re-run forever.
        assert refreshed.pending_alert_events is None


@respx.mock
async def test_recover_refires_and_records_alertlog(test_db, admin_user):
    respx.post(f"https://{_PINNED_IP}/hook").mock(return_value=httpx.Response(200))
    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="D", target="https://hooks.example.com/hook", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.refire",
            name="R",
            publisher="pub",
            version="2.0.0",
            store_url="https://example.com",
            risk_score=60,
            pending_alert_events=json.dumps(
                [{"event_type": "risk_level_change", "old_value": "low", "new_value": "high"}]
            ),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)  # reload expired PK before reading it outside the session
        ext_id = ext.id
        session.add(
            AlertRule(user_id=admin_user.id, destination_id=dest.id, event_type="risk_level_change", enabled=True)
        )
        await session.commit()

    with _patch_resolver():
        async with httpx.AsyncClient() as http:
            await recover_pending_alerts(test_db, http)

    assert respx.calls.call_count == 1  # the dropped alert was re-fired
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
        assert len(logs) == 1
        refreshed = await session.get(Extension, ext_id)
        assert refreshed.pending_alert_events is None  # cleared after successful delivery


def test_deploy_grace_periods_configured():
    compose = (_ROOT / "docker-compose.yml").read_text()
    assert "stop_grace_period:" in compose
    deploy = (_ROOT / "helm" / "iceberg-ebs" / "templates" / "deployment.yaml").read_text()
    assert "terminationGracePeriodSeconds:" in deploy
    values = (_ROOT / "helm" / "iceberg-ebs" / "values.yaml").read_text()
    assert "terminationGracePeriodSeconds:" in values
