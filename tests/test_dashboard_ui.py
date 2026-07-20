"""Server-side pagination / filtering / search on the dashboard UI (#23)."""

from pathlib import Path

from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension


async def _seed(session, admin_user, n, store="chrome"):
    for i in range(n):
        session.add(
            Extension(
                user_id=admin_user.id,
                store=store,
                extension_id=f"a{i:031d}",
                name=f"Ext {i:03d}",
                publisher="Acme",
                version="1.0",
                store_url="https://example.com",
                risk_score=i % 100,
                watchlist=True,
            )
        )
    await session.commit()


async def test_dashboard_paginates(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 60)

    r = await client.get("/")
    assert r.status_code == 200
    assert "Showing 1–25 of 60" in r.text
    assert "Page 1 of 3" in r.text

    r2 = await client.get("/?page=2")
    assert "Showing 26–50 of 60" in r2.text
    assert "Page 2 of 3" in r2.text


async def test_dashboard_filters_by_store(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 5, store="chrome")
        await _seed(s, admin_user, 3, store="edge")

    r = await client.get("/?store=edge")
    assert r.status_code == 200
    assert "Showing 1–3 of 3" in r.text
    assert "(8 total)" in r.text


async def test_dashboard_search(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 30)

    r = await client.get("/?q=Ext%20007")
    assert r.status_code == 200
    assert "Showing 1–1 of 1" in r.text
    assert '"name": "Ext 007"' in r.text


async def test_dashboard_search_no_match(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 5)

    r = await client.get("/?q=nonexistent-xyz")
    assert r.status_code == 200
    assert "No extensions match these filters" in r.text


async def test_dashboard_sort_by_name_asc(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 30)

    r = await client.get("/?sort=name&order=asc")
    assert r.status_code == 200
    # First embedded row is the alphabetically-first name.
    body = r.text
    idx000 = body.find('"name": "Ext 000"')
    idx001 = body.find('"name": "Ext 001"')
    assert 0 < idx000 < idx001


async def test_dashboard_tolerates_bad_params(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 3)
    # Junk query params must not 422 a browser navigation — they fall back.
    r = await client.get("/?store=firefox&risk=spicy&sort=bogus&order=sideways&page=-5")
    assert r.status_code == 200
    assert "Showing 1–3 of 3" in r.text


async def test_dashboard_tolerates_non_numeric_page(client, test_db, admin_user):
    """#152: a mangled / hand-edited non-numeric `page` must render the dashboard (falling
    back to page 1), not raw-422 the way a typed int param did."""
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, 3)
    for page in ("abc", "", "2.5", "1e3"):
        r = await client.get(f"/?page={page}")
        assert r.status_code == 200, page
        assert "Showing 1–3 of 3" in r.text  # fell back to page 1


async def test_detail_page_permission_tiers_derive_from_single_source(client, test_db, admin_user):
    # The rendered tier badges must come from app.permissions (via permission_tier),
    # not a hand-copied template list — the copy had drifted and rendered
    # declarativeNetRequestWithHostAccess (CRITICAL, maxes the score) as a grey
    # "low" tag (#281).
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="c" * 32,
            name="Tiered",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            permissions='["declarativeNetRequestWithHostAccess", "pageCapture", "storage", "someUnknownPerm"]',
            package_analysis='{"host_permissions": ["*://*/*", "https://example.com/*"]}',
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/extensions/{ext_id}")
    assert r.status_code == 200
    # API permissions, tiered from the CRITICAL/HIGH/MEDIUM sets + low fallback.
    assert '<span class="perm-tag perm-critical">declarativeNetRequestWithHostAccess</span>' in r.text
    assert '<span class="perm-tag perm-high">pageCapture</span>' in r.text
    assert '<span class="perm-tag perm-medium">storage</span>' in r.text
    assert '<span class="perm-tag perm-low">someUnknownPerm</span>' in r.text
    # Host permissions: every BROAD_HOST_PATTERNS spelling is critical (the template
    # copy missed *://*/*); scoped host access is high.
    assert '<span class="perm-tag perm-critical">*://*/*</span>' in r.text
    assert '<span class="perm-tag perm-high">https://example.com/*</span>' in r.text


def test_detail_template_carries_no_inlined_tier_or_band_constants():
    # The single-source rule (#63/#281): tier membership lives in app/permissions.py
    # and band cut points in scoring.risk_level. Neither may be re-inlined in the
    # template, where they drift silently.
    source = (Path(__file__).resolve().parent.parent / "app/templates/extension_detail.html").read_text()
    assert "'debugger'" not in source, "permission tier list re-inlined in template (#281)"
    assert "'cookies'" not in source, "permission tier list re-inlined in template (#281)"
    assert "pct < 25" not in source and "pct < 50" not in source, "band thresholds re-inlined in template (#281)"


async def test_detail_page_tolerates_malformed_json(client, test_db, admin_user):
    # A partial write / manual edit can leave invalid JSON in the stored columns;
    # the detail page must fall back instead of 500-ing, like the JSON API (#61).
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="a" * 32,
            name="Broken",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            permissions="{not json",
            risk_detail="{not json",
            package_analysis="{not json",
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/extensions/{ext_id}")
    assert r.status_code == 200
    assert "Broken" in r.text


async def test_detail_page_tolerates_wrong_shaped_json(client, test_db, admin_user):
    # Valid JSON of the wrong container type (a partial write / manual edit) must also
    # fall back rather than AttributeError-ing on .get/.setdefault — the accessor shape
    # guard, not just decode guard (#150/#167).
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="b" * 32,
            name="Misshaped",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            permissions='{"not": "a list"}',
            risk_detail="[1, 2, 3]",
            package_analysis="[1, 2, 3]",  # array where the page expects an object
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/extensions/{ext_id}")
    assert r.status_code == 200
    assert "Misshaped" in r.text


async def test_detail_page_tolerates_non_string_host_permission_member(client, test_db, admin_user):
    # A valid JSON list whose member is a dict/list (partial write / manual edit) must
    # not 500 the detail page: the tier classifier's set-membership check raises
    # TypeError on unhashable members without the string filter (#281 review; same
    # threat model the API DTO already guards, #150).
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="d" * 32,
            name="OddHosts",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            permissions='["storage"]',
            package_analysis='{"host_permissions": ["https://ok.example.com/*", {"bad": 1}, ["nested"], 7]}',
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/extensions/{ext_id}")
    assert r.status_code == 200
    assert '<span class="perm-tag perm-high">https://ok.example.com/*</span>' in r.text


async def test_latest_fetch_logs_picks_newest_with_deterministic_tiebreak(test_db, admin_user):
    # The DISTINCT ON rewrite (#284) must keep the latest-log-per-extension contract,
    # with id DESC breaking exact-timestamp ties (newest row wins).
    from datetime import datetime, timezone

    from app.models import FetchLog
    from app.routes.ui import _latest_fetch_logs

    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="e" * 32,
            name="Logged",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id
        t1 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)
        s.add(FetchLog(extension_id=ext_id, success=True, fetched_at=t1))
        s.add(FetchLog(extension_id=ext_id, success=False, fetched_at=t2))
        s.add(FetchLog(extension_id=ext_id, success=True, fetched_at=t2))  # same ts, higher id
        await s.commit()

        latest = await _latest_fetch_logs(s, [ext_id])
    assert latest[ext_id].fetched_at.replace(tzinfo=timezone.utc) == t2
    assert latest[ext_id].success is True  # id DESC tie-break: the later insert wins


def test_latest_fetch_logs_query_is_bounded_per_extension():
    # #284 review: the dashboard's latest-log lookup must retrieve ONE indexed row
    # per extension (a correlated LATERAL ... LIMIT 1), not scan-and-dedupe every
    # FetchLog row (the earlier DISTINCT ON stayed linear in total history despite
    # the composite index). Assert on the compiled SQL so a regression back to
    # DISTINCT ON — which renders neither LATERAL nor LIMIT — fails here.
    from sqlalchemy.dialects import postgresql

    from app.routes.ui import _latest_fetch_logs_stmt

    sql = str(
        _latest_fetch_logs_stmt([1, 2, 3]).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    ).upper()
    assert "LATERAL" in sql, sql
    assert "LIMIT 1" in sql, sql
    assert "DISTINCT" not in sql, sql
