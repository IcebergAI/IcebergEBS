"""Graceful shutdown / recoverable alerts (#109).

A shutdown landing between a committed state change and its webhook delivery must not
silently drop the alert: fetch_and_store stages the pending events in the same commit,
and recover_pending_alerts re-fires them on the next startup/cycle.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import respx
from sqlalchemy import update as sa_update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import ExtensionMetadata, FetchError
from app.models import AlertDestination, AlertLog, AlertRule, Extension
from app.services import _clear_pending_alerts, fetch_and_store, recover_pending_alerts

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
        dest_id = dest.id  # capture now: the ext commit below re-expires every instance in the session
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
            AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="risk_level_change", enabled=True)
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


@respx.mock
async def test_concurrent_recover_delivers_each_pending_alert_once(test_db, admin_user):
    """The backgrounded startup recovery (#155) can overlap the scheduler cycle's recovery when
    a slow backlog outlives the fetch interval. The shared _recovery_lock must serialise them so
    a pending alert is delivered exactly once — not duplicated by two scans reading the same
    marker before either compare-and-clears it (#155 review)."""
    respx.post(f"https://{_PINNED_IP}/hook").mock(return_value=httpx.Response(200))
    async with AsyncSession(test_db) as session:
        dest = AlertDestination(user_id=admin_user.id, label="D", target="https://hooks.example.com/hook", enabled=True)
        session.add(dest)
        await session.commit()
        await session.refresh(dest)
        dest_id = dest.id
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.concurrent_recover",
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
        await session.refresh(ext)
        ext_id = ext.id
        session.add(
            AlertRule(user_id=admin_user.id, destination_id=dest_id, event_type="risk_level_change", enabled=True)
        )
        await session.commit()

    with _patch_resolver():
        async with httpx.AsyncClient() as http:
            # Two recoveries racing — without the lock both scan the still-set marker and deliver.
            await asyncio.gather(recover_pending_alerts(test_db, http), recover_pending_alerts(test_db, http))

    assert respx.calls.call_count == 1  # delivered exactly once, not duplicated
    async with AsyncSession(test_db) as session:
        logs = (await session.exec(select(AlertLog))).all()
        assert len(logs) == 1
        assert (await session.get(Extension, ext_id)).pending_alert_events is None  # cleared


async def test_fetch_and_store_merges_prior_pending_events(test_db, admin_user):
    """A prior failed delivery left events in the marker; a new refresh must MERGE them with
    the newly detected events, never overwrite or drop them (#109 review)."""
    prior = {"event_type": "risk_level_change", "old_value": "low", "new_value": "high"}
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.merge",
            name="M",
            publisher="pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=10,
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),  # not first fetch
            pending_alert_events=json.dumps([prior]),  # undelivered from a prior failed fire
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        meta = ExtensionMetadata(
            name="M", publisher="pub", version="2.0.0", store_url="https://example.com"
        )  # version bump → a NEW new_version event
        with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
            MockFetcher.return_value.fetch = AsyncMock(return_value=(meta, None))
            ext, events = await fetch_and_store(ext, session, httpx.AsyncClient())

    staged_types = [e["event_type"] for e in json.loads(ext.pending_alert_events)]
    assert "risk_level_change" in staged_types  # the prior undelivered event survived
    assert "new_version" in staged_types  # the newly detected event was added
    # The caller fires the full merged set, not just this refresh's new events.
    assert [e.event_type for e in events] == staged_types


async def test_clear_pending_alerts_is_compare_and_clear(test_db, admin_user):
    """_clear_pending_alerts must clear only when the marker still equals what was delivered, so
    a slow/older delivery can't wipe a newer marker a concurrent refresh appended to (#109 review)."""
    newer = json.dumps([{"event_type": "new_version", "old_value": "1", "new_value": "3"}])
    older = json.dumps([{"event_type": "new_version", "old_value": "1", "new_value": "2"}])
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.cac",
            name="C",
            publisher="pub",
            version="3.0.0",
            store_url="https://example.com",
            risk_score=10,
            pending_alert_events=newer,
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    # A stale delivery tries to clear an OLDER snapshot — must be a no-op.
    await _clear_pending_alerts(ext_id, test_db, older)
    async with AsyncSession(test_db) as session:
        assert (await session.get(Extension, ext_id)).pending_alert_events == newer

    # Clearing with the matching snapshot succeeds.
    await _clear_pending_alerts(ext_id, test_db, newer)
    async with AsyncSession(test_db) as session:
        assert (await session.get(Extension, ext_id)).pending_alert_events is None


async def test_concurrent_fetch_and_store_preserves_both_events(test_db, admin_user):
    """Two refreshes of the SAME extension overlapping (manual API refresh racing the scheduler)
    must not lose an event. Both load the marker before either commits (barrier), then the
    row-locked re-read in fetch_and_store serialises the merge so both events survive — a plain
    in-memory read-modify-write would last-writer-wins and drop one (#109 review)."""
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.concurrent",
            name="C",
            publisher="pub",
            version="1.0.0",
            store_url="https://example.com",
            risk_score=10,
            last_fetched_at=datetime(2024, 1, 1, tzinfo=timezone.utc),  # not first fetch
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    # Release both fetches only once BOTH refreshes have loaded the extension, so each starts
    # from the same (empty) marker — the exact window a lost-update race needs.
    both_loaded = asyncio.Barrier(2)
    meta = ExtensionMetadata(name="C", publisher="pub", version="2.0.0", store_url="https://example.com")

    async def fetch_after_barrier(*_a, **_k):
        await both_loaded.wait()
        return (meta, None)

    async def one_refresh():
        async with AsyncSession(test_db) as s:
            ext = await s.get(Extension, ext_id)  # both load before either commits
            _, _ = await fetch_and_store(ext, s, httpx.AsyncClient())
            await s.commit()

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=fetch_after_barrier)
        await asyncio.gather(one_refresh(), one_refresh())

    async with AsyncSession(test_db) as session:
        staged = json.loads((await session.get(Extension, ext_id)).pending_alert_events)
    # Each refresh detected a new_version event; the row-locked merge preserved BOTH of them.
    # A lost-update (in-memory read-modify-write) would keep only one refresh's events.
    new_version_events = [e for e in staged if e["event_type"] == "new_version"]
    assert len(new_version_events) == 2


async def test_clear_pending_alerts_loses_race_to_concurrent_append(test_db, admin_user):
    """Genuinely interleaved append vs clear. While the clear's conditional UPDATE is blocked on
    the appender's row lock, the appender commits new events; the clear must then be a no-op (its
    WHERE no longer matches) and never erase the appended event (#109 review)."""
    old = json.dumps([{"event_type": "new_version", "old_value": "1", "new_value": "2"}])
    appended = json.dumps(
        [
            {"event_type": "new_version", "old_value": "1", "new_value": "2"},
            {"event_type": "risk_level_change", "old_value": "low", "new_value": "high"},
        ]
    )
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="pub.race",
            name="R",
            publisher="pub",
            version="2.0.0",
            store_url="https://example.com",
            risk_score=10,
            pending_alert_events=old,
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    committed = asyncio.Event()

    async def appender():
        async with AsyncSession(test_db) as s:
            # Take the row lock and append, holding it so the clear below blocks on it.
            await s.execute(sa_update(Extension).where(Extension.id == ext_id).values(pending_alert_events=appended))
            await asyncio.sleep(0.2)
            await s.commit()
            committed.set()

    async def clearer():
        await asyncio.sleep(0.05)  # let the appender grab the row lock first
        # Blocks on the appender's lock; runs after commit, when the marker is `appended` (not
        # `old`), so the conditional WHERE matches nothing and clears nothing.
        await _clear_pending_alerts(ext_id, test_db, old)

    await asyncio.gather(appender(), clearer())
    assert committed.is_set()
    async with AsyncSession(test_db) as session:
        assert (await session.get(Extension, ext_id)).pending_alert_events == appended


async def test_drain_inflight_awaits_blocked_refresh(test_db, admin_user, monkeypatch):
    """drain_inflight must await an in-flight refresh cycle instead of letting shutdown abandon
    it — APScheduler 3.x's shutdown(wait=True) cannot (#109 review)."""
    from app import scheduler

    monkeypatch.setattr(scheduler, "engine", test_db)
    async with AsyncSession(test_db) as s:
        s.add(
            Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id="pub.block",
                name="B",
                publisher="pub",
                version="1.0",
                store_url="https://example.com",
                risk_score=10,
                watchlist=True,
            )
        )
        await s.commit()

    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_fetch(*_a, **_k):
        started.set()
        await release.wait()
        raise FetchError("released")  # end the cycle cleanly once unblocked

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=blocking_fetch)
        async with httpx.AsyncClient() as http:
            job = asyncio.create_task(scheduler.refresh_watchlist(http))
            await asyncio.wait_for(started.wait(), timeout=5)
            assert scheduler._inflight  # the running cycle registered itself
            drain = asyncio.create_task(scheduler.drain_inflight(timeout=5))
            await asyncio.sleep(0.05)
            assert not drain.done()  # drain blocks on the in-flight cycle
            release.set()
            await asyncio.wait_for(drain, timeout=5)
            assert job.done()
    assert not scheduler._inflight  # deregistered on completion


def test_deploy_grace_periods_configured():
    compose = (_ROOT / "docker-compose.yml").read_text()
    assert "stop_grace_period:" in compose
    deploy = (_ROOT / "helm" / "iceberg-ebs" / "templates" / "deployment.yaml").read_text()
    assert "terminationGracePeriodSeconds:" in deploy
    values = (_ROOT / "helm" / "iceberg-ebs" / "values.yaml").read_text()
    assert "terminationGracePeriodSeconds:" in values
