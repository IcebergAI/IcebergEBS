"""Regression tests for fetch_and_store's keep-stale metadata guards (#142).

A 200-status store response can still be a partial parse — Chrome's HTML
scraper returns publisher="", install_count=None, last_updated=None on a
shifted layout without raising. fetch_and_store must fall back to the stored
values (like it already does for version/permissions) instead of clobbering
the record and swinging the risk score into a spurious risk_level_change.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import ExtensionMetadata
from app.models import Extension, InstallCountHistory
from app.services import fetch_and_store
from tests.conftest import make_fake_crx

RECENT = datetime.now(timezone.utc) - timedelta(days=5)


def _meta(**overrides) -> ExtensionMetadata:
    values = dict(
        name="Test Ext",
        publisher="Store Pub",
        description="desc",
        version="1.0.0",
        install_count=50_000,
        last_updated=RECENT,
        store_url="https://example.com/ext",
        publisher_verified=None,
    )
    values.update(overrides)
    return ExtensionMetadata(**values)


_PARTIAL = dict(publisher="", version="", install_count=None, last_updated=None)


async def _make_ext(test_db, user_id, **overrides) -> int:
    values = dict(
        user_id=user_id,
        store="chrome",
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="Test Ext",
        publisher="",
        version="",
        store_url="https://example.com/ext",
        permissions="[]",
    )
    values.update(overrides)
    async with AsyncSession(test_db) as session:
        ext = Extension(**values)
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        return ext.id


async def _fetch(test_db, ext_id, meta, pkg=None):
    """Run fetch_and_store against a mocked ChromeFetcher and commit."""
    async with httpx.AsyncClient() as http:
        with patch("app.fetchers.ChromeFetcher") as MockFetcher:
            MockFetcher.return_value.fetch = AsyncMock(return_value=(meta, pkg))
            async with AsyncSession(test_db) as session:
                ext = await session.get(Extension, ext_id)
                ext, events = await fetch_and_store(ext, session, http)
                await session.commit()
                await session.refresh(ext)
                return ext, events


async def _history_count(test_db, ext_id) -> int:
    async with AsyncSession(test_db) as session:
        rows = (await session.exec(select(InstallCountHistory).where(InstallCountHistory.extension_id == ext_id))).all()
        return len(rows)


async def test_partial_parse_keeps_stored_metadata_and_score(test_db, admin_user):
    """#142: a partial parse must not clobber stored fields, move the score,
    or emit any change event."""
    ext_id = await _make_ext(test_db, admin_user.id)
    ext, _ = await _fetch(test_db, ext_id, _meta())
    assert ext.publisher == "Store Pub"
    score_after_good_fetch = ext.risk_score

    ext, events = await _fetch(test_db, ext_id, _meta(**_PARTIAL))

    assert ext.publisher == "Store Pub"
    assert ext.install_count == 50_000
    assert ext.last_updated is not None
    assert ext.version == "1.0.0"
    assert ext.risk_score == score_after_good_fetch
    assert events == []
    # No phantom history row for a reading that never happened.
    assert await _history_count(test_db, ext_id) == 1


async def test_partial_parse_uses_stale_values_in_risk_detail(test_db, admin_user):
    """The kept values must actually feed the scorer: staleness/popularity must
    not degrade to their 'unknown' midpoints on a partial parse."""
    ext_id = await _make_ext(test_db, admin_user.id)
    await _fetch(test_db, ext_id, _meta())
    ext, _ = await _fetch(test_db, ext_id, _meta(**_PARTIAL))

    detail = json.loads(ext.risk_detail)
    assert detail["staleness"] == 0  # recent date kept, not the 10-point unknown
    assert detail["popularity"] == 0  # 50k installs kept, not the 10-point unknown
    assert detail["publisher"] == 0  # no publisher_changed +8, no generic-name +3


async def test_genuine_publisher_change_still_fires(test_db, admin_user):
    ext_id = await _make_ext(test_db, admin_user.id)
    await _fetch(test_db, ext_id, _meta())
    ext, events = await _fetch(test_db, ext_id, _meta(publisher="New Pub"))

    assert ext.publisher == "New Pub"
    assert any(e.event_type == "publisher_change" for e in events)
    assert json.loads(ext.risk_detail)["publisher"] >= 8


async def test_zero_install_count_is_real_data(test_db, admin_user):
    """0 is a legitimate reading — the None-sentinel must not treat it as missing."""
    ext_id = await _make_ext(test_db, admin_user.id)
    ext, _ = await _fetch(test_db, ext_id, _meta(install_count=0))
    assert ext.install_count == 0
    assert await _history_count(test_db, ext_id) == 1


async def test_first_fetch_with_partial_metadata(test_db, admin_user):
    """Nothing stored to fall back to: a first fetch persists what it got."""
    ext_id = await _make_ext(test_db, admin_user.id)
    ext, events = await _fetch(test_db, ext_id, _meta(**_PARTIAL))
    assert ext.publisher == ""
    assert ext.install_count is None
    assert events == []  # no prior state to compare against


async def test_manifest_author_never_overrides_stored_publisher(test_db, admin_user):
    """A partial parse + a manifest author differing from the stored publisher
    must not rewrite the publisher (or flap publisher_change alerts)."""
    ext_id = await _make_ext(test_db, admin_user.id)
    await _fetch(test_db, ext_id, _meta())

    pkg = make_fake_crx({"manifest_version": 3, "name": "x", "version": "1", "author": "Manifest Author"})
    ext, events = await _fetch(test_db, ext_id, _meta(**_PARTIAL), pkg=pkg)

    assert ext.publisher == "Store Pub"
    assert not any(e.event_type == "publisher_change" for e in events)


async def test_manifest_author_fills_never_known_publisher(test_db, admin_user):
    """The author fallback's documented purpose: fill the gap when no publisher
    has ever been known from the store."""
    ext_id = await _make_ext(test_db, admin_user.id)
    pkg = make_fake_crx({"manifest_version": 3, "name": "x", "version": "1", "author": "Manifest Author"})
    ext, _ = await _fetch(test_db, ext_id, _meta(**_PARTIAL), pkg=pkg)
    assert ext.publisher == "Manifest Author"


async def test_fresh_values_still_overwrite(test_db, admin_user):
    """The guards must not freeze the record: a good fetch updates everything."""
    ext_id = await _make_ext(test_db, admin_user.id)
    await _fetch(test_db, ext_id, _meta())
    newer = datetime.now(timezone.utc) - timedelta(days=1)
    ext, _ = await _fetch(test_db, ext_id, _meta(publisher="Store Pub", install_count=60_000, last_updated=newer))
    assert ext.install_count == 60_000
    assert ext.last_updated == newer
    assert await _history_count(test_db, ext_id) == 2
