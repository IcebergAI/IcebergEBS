from datetime import datetime, timedelta, timezone

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.models import AlertLog, Extension, FetchLog, InstallCountHistory, InstallObservation
from app.retention import prune_expired, refresh_install_footprints


async def _make_extension(session: AsyncSession) -> int:
    ext = Extension(
        store="chrome",
        extension_id="a" * 32,
        name="E",
        publisher="p",
        version="1.0",
        store_url="https://example.com",
    )
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ext.id


async def test_prune_removes_old_keeps_recent(session):
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    old = now - timedelta(days=100)
    recent = now - timedelta(days=10)

    session.add(FetchLog(extension_id=ext_id, success=True, fetched_at=old))
    session.add(FetchLog(extension_id=ext_id, success=True, fetched_at=recent))
    session.add(InstallCountHistory(extension_id=ext_id, install_count=1, recorded_at=old))
    session.add(InstallCountHistory(extension_id=ext_id, install_count=2, recorded_at=recent))
    session.add(AlertLog(extension_id=ext_id, event_type="new_version", detail="{}", success=True, sent_at=old))
    session.add(AlertLog(extension_id=ext_id, event_type="new_version", detail="{}", success=True, sent_at=recent))
    # InstallObservation prunes on last_seen (#287): a pair the SOAR keeps re-pushing
    # stays; one it stopped reporting expires with the same retention window.
    session.add(InstallObservation(extension_id=ext_id, asset_id="old-host", first_seen=old, last_seen=old))
    session.add(InstallObservation(extension_id=ext_id, asset_id="live-host", first_seen=old, last_seen=recent))
    await session.commit()

    counts = await prune_expired(session, retention_days=30, now=now)
    await session.commit()

    assert counts == {"FetchLog": 1, "InstallCountHistory": 1, "AlertLog": 1, "InstallObservation": 1}

    # Only the recent row of each table remains.
    for model in (FetchLog, InstallCountHistory, AlertLog, InstallObservation):
        rows = (await session.exec(select(model))).all()
        assert len(rows) == 1

    # The extension itself is untouched.
    assert await session.get(Extension, ext_id) is not None


async def test_prune_disabled_is_noop(session):
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    session.add(FetchLog(extension_id=ext_id, success=True, fetched_at=now - timedelta(days=999)))
    await session.commit()

    counts = await prune_expired(session, retention_days=0, now=now)
    await session.commit()

    assert counts == {"FetchLog": 0, "InstallCountHistory": 0, "AlertLog": 0, "InstallObservation": 0}
    assert len((await session.exec(select(FetchLog))).all()) == 1


async def test_scheduler_registers_prune_job_only_when_enabled(monkeypatch):
    import httpx

    from app import scheduler as scheduler_mod
    from app.config import settings

    client = httpx.AsyncClient()
    try:
        monkeypatch.setattr(settings, "retention_days", 0)
        sched = scheduler_mod.create_scheduler(client)
        assert sched.get_job("retention_prune") is None

        monkeypatch.setattr(settings, "retention_days", 30)
        sched = scheduler_mod.create_scheduler(client)
        assert sched.get_job("retention_prune") is not None
    finally:
        await client.aclose()


async def test_scheduler_prune_first_fire_is_at_startup_not_in_24h(monkeypatch):
    """#145: the prune job's first fire must be at startup, not +24h — otherwise a
    deployment that restarts more often than daily would never prune despite retention
    being enabled."""
    import httpx

    from app import scheduler as scheduler_mod
    from app.config import settings

    client = httpx.AsyncClient()
    try:
        monkeypatch.setattr(settings, "retention_days", 30)
        sched = scheduler_mod.create_scheduler(client)
        job = sched.get_job("retention_prune")
        assert job is not None
        # next_run_time is set (not the interval trigger's default start+24h) and is at/near now.
        assert isinstance(job.next_run_time, datetime)
        assert job.next_run_time <= datetime.now(timezone.utc) + timedelta(minutes=1)
    finally:
        await client.aclose()


async def test_scheduler_jobs_disable_misfire_grace_time(monkeypatch):
    """#198: both scheduler jobs set misfire_grace_time=None. APScheduler's 1s default would
    silently drop a due fire when the single-worker loop is busy/stalled at fire time. For the
    prune's at-startup fire that means a >1s gap between create_scheduler() stamping
    next_run_time and the executor picking it up (a CPU-starved restart — the exact scenario
    #145 targets) skips the prune entirely until +24h. None removes the limit so it always runs."""
    import httpx

    from app import scheduler as scheduler_mod
    from app.config import settings

    client = httpx.AsyncClient()
    try:
        monkeypatch.setattr(settings, "retention_days", 30)
        sched = scheduler_mod.create_scheduler(client)
        # Explicitly set to None (not APScheduler's 1s default) on both jobs.
        assert sched.get_job("watchlist_refresh").misfire_grace_time is None
        assert sched.get_job("retention_prune").misfire_grace_time is None
    finally:
        await client.aclose()


# ---- install-footprint decay (#287) ----------------------------------------


async def test_stale_observation_stops_counting_after_window(session, monkeypatch):
    monkeypatch.setattr(settings, "inventory_freshness_days", 30)
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    session.add(InstallObservation(extension_id=ext_id, asset_id="fresh", first_seen=now, last_seen=now))
    session.add(
        InstallObservation(extension_id=ext_id, asset_id="stale", first_seen=now, last_seen=now - timedelta(days=45))
    )
    ext = await session.get(Extension, ext_id)
    ext.install_footprint = 2  # the pre-decay cached value
    session.add(ext)
    await session.commit()

    updated = await refresh_install_footprints(session, now=now)
    await session.commit()
    assert updated >= 1
    ext = await session.get(Extension, ext_id)
    await session.refresh(ext)
    assert ext.install_footprint == 1  # the stale asset no longer counts


async def test_all_stale_observations_decay_footprint_to_zero(session, monkeypatch):
    # The #287 failure case: the extension stops appearing in SOAR pushes entirely,
    # so the per-batch recompute never touches it — the daily refresh must decay it.
    monkeypatch.setattr(settings, "inventory_freshness_days", 30)
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    session.add(
        InstallObservation(extension_id=ext_id, asset_id="gone", first_seen=now, last_seen=now - timedelta(days=90))
    )
    ext = await session.get(Extension, ext_id)
    ext.install_footprint = 1
    session.add(ext)
    await session.commit()

    await refresh_install_footprints(session, now=now)
    await session.commit()
    ext = await session.get(Extension, ext_id)
    await session.refresh(ext)
    assert ext.install_footprint == 0


async def test_decay_disabled_counts_all_observations(session, monkeypatch):
    monkeypatch.setattr(settings, "inventory_freshness_days", 0)
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    session.add(
        InstallObservation(extension_id=ext_id, asset_id="ancient", first_seen=now, last_seen=now - timedelta(days=900))
    )
    ext = await session.get(Extension, ext_id)
    ext.install_footprint = 0
    session.add(ext)
    await session.commit()

    await refresh_install_footprints(session, now=now)
    await session.commit()
    ext = await session.get(Extension, ext_id)
    await session.refresh(ext)
    assert ext.install_footprint == 1  # pre-#287 behaviour preserved when disabled


async def test_retention_recomputes_footprint_when_decay_disabled(session, monkeypatch):
    # Retention enabled + decay disabled (#287 review): the daily footprint-refresh job is
    # NOT registered when inventory_freshness_days <= 0, so if retention deletes the old
    # observations without recomputing, the cached footprint (and exposure) stays inflated
    # while the live department breakdown is empty. The prune must recompute in-band.
    monkeypatch.setattr(settings, "inventory_freshness_days", 0)  # decay disabled
    ext_id = await _make_extension(session)
    now = datetime(2026, 6, 26, tzinfo=timezone.utc)
    # One asset within the retention window, one beyond it.
    session.add(
        InstallObservation(extension_id=ext_id, asset_id="kept", first_seen=now, last_seen=now - timedelta(days=10))
    )
    session.add(
        InstallObservation(extension_id=ext_id, asset_id="gone", first_seen=now, last_seen=now - timedelta(days=100))
    )
    ext = await session.get(Extension, ext_id)
    ext.install_footprint = 2  # cached "count all observations" value
    session.add(ext)
    await session.commit()

    counts = await prune_expired(session, retention_days=30, now=now)
    await session.commit()
    assert counts["InstallObservation"] == 1  # the beyond-window row was pruned
    ext = await session.get(Extension, ext_id)
    await session.refresh(ext)
    assert ext.install_footprint == 1  # recomputed over the surviving observation
