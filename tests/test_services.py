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
from app.inspector import PackageAnalysis
from app.models import Extension, InstallCountHistory
from app.scoring import compute_risk_score
from app.services import _apply_fetch_results, _effective_values, fetch_and_store
from tests.conftest import make_fake_crx, make_zip

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


async def test_sudden_drop_uses_the_two_most_recent_readings(test_db, admin_user):
    """#146: replacing the full install-count history scan with a two-row lookup
    must still fire the >30% sudden-drop popularity bonus, computed from the two
    most recent readings even behind a long steady history."""
    ext_id = await _make_ext(test_db, admin_user.id)
    # A deep, all-identical history — no reading is itself a drop.
    for _ in range(5):
        await _fetch(test_db, ext_id, _meta(install_count=1_000))

    # Final reading falls 40% from the immediately preceding 1_000.
    ext, _ = await _fetch(test_db, ext_id, _meta(install_count=600))

    # base 8 (600 < 1_000) + 10 sudden-drop bonus.
    assert json.loads(ext.risk_detail)["popularity"] == 18
    # Every reading is still persisted; only the *read* side is bounded.
    assert await _history_count(test_db, ext_id) == 6


async def test_no_drop_bonus_when_recent_readings_are_steady(test_db, admin_user):
    """Control for the two-row lookup: a steady immediately-preceding reading
    must not be misread as a drop (guards the reconstruction ordering)."""
    ext_id = await _make_ext(test_db, admin_user.id)
    for _ in range(5):
        await _fetch(test_db, ext_id, _meta(install_count=600))
    ext, _ = await _fetch(test_db, ext_id, _meta(install_count=600))

    assert json.loads(ext.risk_detail)["popularity"] == 8  # base only, no bonus


# ---------------------------------------------------------------------------
# Unit tests for the pure helpers extracted from fetch_and_store (#166).
# These exercise the keep-stale fallback rules and the row mutation directly,
# without the fetch pipeline or a DB.
# ---------------------------------------------------------------------------


def _plain_ext(**overrides) -> Extension:
    values = dict(
        user_id=1,
        store="chrome",
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="Test Ext",
        publisher="",
        version="",
        store_url="https://example.com/ext",
        permissions="[]",
    )
    values.update(overrides)
    return Extension(**values)


def _risk():
    return compute_risk_score(
        permissions=[],
        host_permissions=[],
        install_count=1000,
        install_history=[],
        publisher="x",
        publisher_changed=False,
        publisher_verified=None,
        last_updated=None,
        analysis=None,
    )


def test_effective_values_uses_analysis_when_present():
    ext = _plain_ext()
    analysis = PackageAnalysis(permissions=["tabs"], host_permissions=["<all_urls>"], author="Manifest Guy")
    eff = _effective_values(ext, _meta(**_PARTIAL), analysis)
    assert eff.permissions == ["tabs"]
    assert eff.host_permissions == ["<all_urls>"]
    # Author fills the publisher gap only when nothing store-sourced/stored exists.
    assert eff.publisher == "Manifest Guy"


def test_effective_values_falls_back_to_stored_on_failed_inspection():
    ext = _plain_ext(
        publisher="Store Pub",
        install_count=50_000,
        last_updated=RECENT,
        permissions='["storage"]',
        package_analysis='{"host_permissions": ["https://stored.example/*"]}',
    )
    # analysis=None (download/inspection failed) + partial scrape → keep stored.
    eff = _effective_values(ext, _meta(**_PARTIAL), None)
    assert eff.permissions == ["storage"]
    assert eff.host_permissions == ["https://stored.example/*"]
    assert eff.publisher == "Store Pub"
    assert eff.install_count == 50_000
    assert eff.last_updated == RECENT


def test_effective_values_publisher_changed_requires_nonempty_store_publisher():
    ext = _plain_ext(publisher="Old Pub", last_fetched_at=RECENT)
    assert _effective_values(ext, _meta(publisher="New Pub"), None).publisher_changed is True
    # A partial parse (empty store publisher) is not a change signal.
    assert _effective_values(ext, _meta(publisher=""), None).publisher_changed is False


def test_apply_fetch_results_keeps_version_and_permissions_on_failed_inspection():
    ext = _plain_ext(version="1.2.3", permissions='["storage"]', package_analysis='{"host_permissions": []}')
    eff = _effective_values(ext, _meta(**_PARTIAL), None)
    _apply_fetch_results(ext, _meta(**_PARTIAL), None, eff, _risk())
    # Empty store version must not clobber the stored one.
    assert ext.version == "1.2.3"
    # analysis=None → permissions / package_analysis are left untouched.
    assert ext.permissions == '["storage"]'
    assert ext.package_analysis == '{"host_permissions": []}'


def test_apply_fetch_results_writes_fresh_values():
    ext = _plain_ext(version="1.0.0")
    analysis = PackageAnalysis(permissions=["tabs"], host_permissions=["<all_urls>"])
    eff = _effective_values(ext, _meta(version="2.0.0"), analysis)
    _apply_fetch_results(ext, _meta(version="2.0.0"), analysis, eff, _risk())
    assert ext.version == "2.0.0"
    assert json.loads(ext.permissions) == ["tabs"]
    assert json.loads(ext.package_analysis)["host_permissions"] == ["<all_urls>"]
    assert ext.risk_score == _risk().total
    assert ext.last_fetched_at is not None


async def test_bomd_manifest_does_not_clobber_permissions_or_fire_a_removal_alert(test_db, admin_user):
    """#274 end to end.

    A manifest Chrome tolerates but `json.loads` rejects (here a UTF-8 BOM) used
    to leave `manifest=None` while the analysis object itself stayed truthy — so
    `_effective_values` took its empty permission list over the stored one,
    `_apply_fetch_results` wrote `permissions = "[]"`, and the extension lost its
    permission points *and* fired a spurious `permission_change` "removal".
    """
    ext_id = await _make_ext(test_db, admin_user.id)
    good = make_fake_crx(
        {
            "manifest_version": 3,
            "name": "Test Ext",
            "version": "1.0.0",
            "permissions": ["tabs", "webRequest"],
            "host_permissions": ["<all_urls>"],
        }
    )
    ext, _ = await _fetch(test_db, ext_id, _meta(), pkg=good)
    assert set(json.loads(ext.permissions)) == {"tabs", "webRequest"}
    score_before = ext.risk_score

    # Same extension, next refresh: the store now serves a BOM'd manifest.
    bomd = make_zip(
        {
            "manifest.json": "﻿"
            + json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test Ext",
                    "version": "1.0.0",
                    "permissions": ["tabs", "webRequest"],
                    "host_permissions": ["<all_urls>"],
                }
            ),
            "background.js": "console.log(1);",
        }
    )
    ext, events = await _fetch(test_db, ext_id, _meta(), pkg=bomd)

    # It parses now, so nothing changed at all.
    assert set(json.loads(ext.permissions)) == {"tabs", "webRequest"}
    assert ext.risk_score == score_before
    assert [e.event for e in events] == []


async def test_unparsable_manifest_keeps_stored_permissions(test_db, admin_user):
    """The guard behind the parse fix: even when a manifest genuinely cannot be
    read, the stored permissions must survive rather than being zeroed."""
    ext_id = await _make_ext(test_db, admin_user.id)
    good = make_fake_crx(
        {
            "manifest_version": 3,
            "name": "Test Ext",
            "version": "1.0.0",
            "permissions": ["tabs", "webRequest"],
            "host_permissions": ["<all_urls>"],
        }
    )
    ext, _ = await _fetch(test_db, ext_id, _meta(), pkg=good)
    assert set(json.loads(ext.permissions)) == {"tabs", "webRequest"}

    broken = make_zip({"manifest.json": "{ not valid json", "background.js": "console.log(1);"})
    ext, events = await _fetch(test_db, ext_id, _meta(), pkg=broken)

    assert set(json.loads(ext.permissions)) == {"tabs", "webRequest"}
    assert "permission_change" not in [e.event for e in events]
