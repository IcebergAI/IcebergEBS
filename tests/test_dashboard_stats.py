"""Unit tests for the dashboard stat/URL helpers extracted from the route (#165).

Before the extraction none of this logic (fetch-health counting, the store-outage
exemption from #108, the top-exposure ordering, the URL-cleaning rules) could be
exercised without rendering the whole page. These drive the helpers directly.
"""

from datetime import datetime, timedelta, timezone

from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension, FetchLog
from app.routes.ui import _build_qs, _export_url, _fleet_stats, _is_stale, _top_exposure

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
STALE_AFTER = timedelta(minutes=60)


# ---------------------------------------------------------------------------
# _is_stale (pure)
# ---------------------------------------------------------------------------


def test_is_stale_non_watchlist_is_never_stale():
    assert _is_stale(False, None, NOW, STALE_AFTER) is False
    assert _is_stale(False, NOW - timedelta(days=30), NOW, STALE_AFTER) is False


def test_is_stale_watchlist_never_fetched_is_stale():
    assert _is_stale(True, None, NOW, STALE_AFTER) is True


def test_is_stale_recent_vs_old():
    assert _is_stale(True, NOW - timedelta(minutes=30), NOW, STALE_AFTER) is False
    assert _is_stale(True, NOW - timedelta(minutes=90), NOW, STALE_AFTER) is True


def test_is_stale_coerces_naive_datetime_to_utc():
    naive_old = (NOW - timedelta(minutes=90)).replace(tzinfo=None)
    assert _is_stale(True, naive_old, NOW, STALE_AFTER) is True


# ---------------------------------------------------------------------------
# _build_qs / _export_url (pure)
# ---------------------------------------------------------------------------


def _base(**kw) -> dict:
    params = {"store": None, "risk": None, "q": None, "sort": "risk_score", "order": "desc", "page": 1}
    params.update(kw)
    return params


def test_build_qs_drops_defaults_to_clean_root():
    qs = _build_qs(_base())
    assert qs() == "/"


def test_build_qs_override_page_keeps_only_non_default():
    qs = _build_qs(_base())
    assert qs(page=2) == "/?page=2"


def test_build_qs_preserves_active_filters_and_drops_page_one():
    qs = _build_qs(_base(store="chrome", risk="high", page=3))
    # page=1 override drops the page param; store/risk survive.
    assert qs(page=1) == "/?store=chrome&risk=high"


def test_build_qs_none_override_removes_param():
    qs = _build_qs(_base(store="edge"))
    assert qs(store=None) == "/"


def test_export_url_includes_filters_and_drops_none():
    url = _export_url("csv", store="chrome", risk=None, q="foo", sort="risk_score", order="desc")
    assert url.startswith("/api/extensions/export?")
    assert "format=csv" in url
    assert "store=chrome" in url
    assert "q=foo" in url
    assert "risk=" not in url  # None dropped


# ---------------------------------------------------------------------------
# _fleet_stats (DB-backed)
# ---------------------------------------------------------------------------


async def _add_ext(session, admin_user, idx, *, watchlist, risk_score, last_fetched_at):
    ext = Extension(
        user_id=admin_user.id,
        store="chrome",
        extension_id=f"a{idx:031d}",
        name=f"Ext {idx}",
        publisher="Acme",
        version="1.0",
        store_url="https://example.com",
        risk_score=risk_score,
        watchlist=watchlist,
        last_fetched_at=last_fetched_at,
    )
    session.add(ext)
    await session.flush()
    return ext.id


async def _add_log(session, ext_id, *, success, store_outage=False):
    session.add(FetchLog(extension_id=ext_id, success=success, store_outage=store_outage, fetched_at=NOW))


async def test_fleet_stats_counts_and_health(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        # A: fresh, healthy, high risk
        a = await _add_ext(s, admin_user, 1, watchlist=True, risk_score=80, last_fetched_at=NOW)
        await _add_log(s, a, success=True)
        # B: fresh but last fetch failed (extension's fault) -> unhealthy
        b = await _add_ext(s, admin_user, 2, watchlist=True, risk_score=10, last_fetched_at=NOW)
        await _add_log(s, b, success=False)
        # C: fresh, last fetch was a store-outage skip -> NOT unhealthy (#108), high risk
        c = await _add_ext(s, admin_user, 3, watchlist=True, risk_score=60, last_fetched_at=NOW)
        await _add_log(s, c, success=False, store_outage=True)
        # D: successful but stale (old) -> unhealthy
        d = await _add_ext(
            s, admin_user, 4, watchlist=True, risk_score=None, last_fetched_at=NOW - timedelta(minutes=200)
        )
        await _add_log(s, d, success=True)
        # E: non-watchlist, high risk, never counted as unhealthy
        await _add_ext(s, admin_user, 5, watchlist=False, risk_score=90, last_fetched_at=None)
        # F: watchlist, never fetched, no log -> stale -> unhealthy, high risk
        await _add_ext(s, admin_user, 6, watchlist=True, risk_score=50, last_fetched_at=None)
        await s.commit()

        stats = await _fleet_stats(s, admin_user.id, NOW, STALE_AFTER)

    assert stats.extensions_count == 6
    assert stats.watchlist_count == 5  # all but E
    assert stats.high_risk == 4  # A(80), C(60), E(90), F(50)
    assert stats.unhealthy == 3  # B (failing), D (stale), F (never fetched)
    assert stats.last_refresh == NOW  # newest last_fetched_at across the fleet
    assert stats.next_refresh is not None and stats.next_refresh > NOW


async def test_fleet_stats_empty_fleet(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        stats = await _fleet_stats(s, admin_user.id, NOW, STALE_AFTER)
    assert stats.extensions_count == 0
    assert stats.unhealthy == 0
    assert stats.last_refresh is None
    assert stats.next_refresh is None
    assert stats.latest_logs == {}


# ---------------------------------------------------------------------------
# _top_exposure (DB-backed)
# ---------------------------------------------------------------------------


async def test_top_exposure_orders_by_risk_times_footprint(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        # exposure = risk × footprint
        specs = [
            ("low", 10, 10, 100),
            ("mid", 50, 40, 2000),
            ("high", 90, 100, 9000),
        ]
        for i, (name, risk, footprint, _exp) in enumerate(specs):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="chrome",
                    extension_id=f"b{i:031d}",
                    name=name,
                    publisher="Acme",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=risk,
                    install_footprint=footprint,
                    watchlist=True,
                )
            )
        # Excluded from top-exposure: no footprint, and footprint but no score
        # (exposure is NULL when either factor is unset).
        s.add(
            Extension(
                user_id=admin_user.id,
                store="chrome",
                extension_id=f"c{0:031d}",
                name="no-footprint",
                publisher="Acme",
                version="1.0",
                store_url="https://example.com",
                risk_score=99,
                install_footprint=None,
                watchlist=True,
            )
        )
        s.add(
            Extension(
                user_id=admin_user.id,
                store="chrome",
                extension_id=f"c{1:031d}",
                name="no-score",
                publisher="Acme",
                version="1.0",
                store_url="https://example.com",
                risk_score=None,
                install_footprint=500,
                watchlist=True,
            )
        )
        await s.commit()

        top = await _top_exposure(s, admin_user.id)

    assert [t["name"] for t in top] == ["high", "mid", "low"]
    assert top[0]["exposure"] == 9000
    excluded = {"no-footprint", "no-score"}
    assert all(t["name"] not in excluded for t in top)


async def test_top_exposure_limits_to_five(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        for i in range(8):
            s.add(
                Extension(
                    user_id=admin_user.id,
                    store="chrome",
                    extension_id=f"d{i:031d}",
                    name=f"e{i}",
                    publisher="Acme",
                    version="1.0",
                    store_url="https://example.com",
                    risk_score=10 + i,
                    install_footprint=100,
                    watchlist=True,
                )
            )
        await s.commit()
        top = await _top_exposure(s, admin_user.id)
    assert len(top) == 5
