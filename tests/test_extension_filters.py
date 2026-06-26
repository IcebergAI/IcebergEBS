"""Pagination / filtering / search / sort on GET /api/extensions (#23)."""

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension


async def _seed(session, admin_user, specs):
    """specs: list of (extension_id, store, publisher, risk_score, name)."""
    for ext_id, store, publisher, score, name in specs:
        session.add(
            Extension(
                user_id=admin_user.id,
                store=store,
                extension_id=ext_id,
                name=name,
                publisher=publisher,
                version="1.0",
                store_url="https://example.com",
                risk_score=score,
                watchlist=True,
            )
        )
    await session.commit()


async def test_pagination_bounds_and_total(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, [(f"{'a'}{i:031d}", "chrome", "Acme", i % 100, f"Ext {i}") for i in range(250)])

    r = await client.get("/api/extensions")
    body = r.json()
    assert body["total"] == 250
    assert body["limit"] == 50
    assert len(body["items"]) == 50

    # Custom page window.
    r2 = await client.get("/api/extensions?limit=10&offset=240")
    assert len(r2.json()["items"]) == 10

    # Offset past the end yields an empty page but the true total.
    r3 = await client.get("/api/extensions?limit=10&offset=1000")
    assert r3.json()["items"] == []
    assert r3.json()["total"] == 250

    # Bounds: limit must be 1..200, offset >= 0.
    assert (await client.get("/api/extensions?limit=0")).status_code == 422
    assert (await client.get("/api/extensions?limit=201")).status_code == 422
    assert (await client.get("/api/extensions?offset=-1")).status_code == 422


async def test_filter_by_store(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 10, "C"),
                ("b" * 32, "edge", "Acme", 10, "E"),
                ("pub.vsc", "vscode", "Acme", 10, "V"),
            ],
        )
    r = await client.get("/api/extensions?store=edge")
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["store"] == "edge"


@pytest.mark.parametrize(
    "level,expected_scores",
    [
        ("critical", {80, 75}),
        ("high", {50, 74}),
        ("medium", {25, 49}),
        ("low", {0, 24}),
    ],
)
async def test_filter_by_risk_level(client, test_db, admin_user, level, expected_scores):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "P", 80, "a"),
                ("b" * 32, "chrome", "P", 75, "b"),
                ("c" * 32, "chrome", "P", 74, "c"),
                ("d" * 32, "chrome", "P", 50, "d"),
                ("e" * 32, "chrome", "P", 49, "e"),
                ("f" * 32, "chrome", "P", 25, "f"),
                ("g" * 32, "chrome", "P", 24, "g"),
                ("h" * 32, "chrome", "P", 0, "h"),
            ],
        )
    r = await client.get(f"/api/extensions?risk={level}")
    scores = {e["risk_score"] for e in r.json()["items"]}
    assert scores == expected_scores


async def test_filter_by_publisher(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 10, "a"),
                ("b" * 32, "chrome", "Globex", 10, "b"),
            ],
        )
    r = await client.get("/api/extensions?publisher=Globex")
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["publisher"] == "Globex"


async def test_search_matches_name_publisher_id(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 10, "Password Manager"),
                ("b" * 32, "chrome", "Keepers Inc", 10, "Notes"),
                ("keeper.id" + "x" * 8, "vscode", "Other", 10, "Misc"),
            ],
        )
    # name match
    assert len((await client.get("/api/extensions?q=password")).json()["items"]) == 1
    # publisher + id match for "keeper"
    ids = {e["extension_id"] for e in (await client.get("/api/extensions?q=keeper")).json()["items"]}
    assert "b" * 32 in ids and "keeper.idxxxxxxxx" in ids


async def test_search_escapes_wildcards(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "P", 10, "100% safe"),
                ("b" * 32, "chrome", "P", 10, "totally safe"),
            ],
        )
    # '%' is a literal, not a wildcard — only the "100% safe" row matches.
    items = (await client.get("/api/extensions?q=%25 safe")).json()["items"]
    assert len(items) == 1 and items[0]["name"] == "100% safe"


async def test_sort_by_name_and_score(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "P", 10, "Charlie"),
                ("b" * 32, "chrome", "P", 90, "Alpha"),
                ("c" * 32, "chrome", "P", 50, "Bravo"),
            ],
        )
    names = [e["name"] for e in (await client.get("/api/extensions?sort=name&order=asc")).json()["items"]]
    assert names == ["Alpha", "Bravo", "Charlie"]

    scores = [e["risk_score"] for e in (await client.get("/api/extensions?sort=risk_score&order=desc")).json()["items"]]
    assert scores == [90, 50, 10]


async def test_invalid_filter_values_rejected(client):
    assert (await client.get("/api/extensions?store=firefox")).status_code == 422
    assert (await client.get("/api/extensions?risk=spicy")).status_code == 422
    assert (await client.get("/api/extensions?sort=bogus")).status_code == 422
    assert (await client.get("/api/extensions?order=sideways")).status_code == 422
