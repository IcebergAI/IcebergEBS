"""Server-side pagination / filtering / search on the dashboard UI (#23)."""

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
