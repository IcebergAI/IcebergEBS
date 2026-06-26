"""Export endpoint GET /api/extensions/export?format=csv|json (#25)."""

import csv
import io

from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension


async def _seed(session, admin_user, specs):
    for ext_id, store, publisher, score, name, perms in specs:
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
                permissions=perms,
            )
        )
    await session.commit()


async def test_export_csv(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 80, "Alpha", '["tabs", "storage"]'),
                ("b" * 32, "edge", "Globex", 10, "Bravo", "[]"),
            ],
        )

    r = await client.get("/api/extensions/export")  # default format=csv
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "marvin-extensions.csv" in r.headers["content-disposition"]

    reader = list(csv.DictReader(io.StringIO(r.text)))
    assert len(reader) == 2
    by_name = {row["name"]: row for row in reader}
    assert by_name["Alpha"]["risk_score"] == "80"
    assert by_name["Alpha"]["risk_level"] == "critical"
    assert by_name["Alpha"]["permissions"] == "tabs;storage"
    assert by_name["Bravo"]["store"] == "edge"


async def test_export_json(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 80, "Alpha", '["tabs"]'),
            ],
        )

    r = await client.get("/api/extensions/export?format=json")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["name"] == "Alpha"
    assert rows[0]["risk_level"] == "critical"
    assert rows[0]["permissions"] == "tabs"


async def test_export_respects_filters(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(
            s,
            admin_user,
            [
                ("a" * 32, "chrome", "Acme", 80, "Alpha", "[]"),
                ("b" * 32, "edge", "Globex", 10, "Bravo", "[]"),
                ("c" * 32, "edge", "Globex", 90, "Charlie", "[]"),
            ],
        )

    r = await client.get("/api/extensions/export?format=json&store=edge")
    names = {row["name"] for row in r.json()}
    assert names == {"Bravo", "Charlie"}

    r2 = await client.get("/api/extensions/export?format=json&risk=critical")
    names2 = {row["name"] for row in r2.json()}
    assert names2 == {"Alpha", "Charlie"}


async def test_export_empty_csv_has_header(client):
    r = await client.get("/api/extensions/export")
    assert r.status_code == 200
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("id,store,extension_id,name,publisher")


async def test_export_invalid_format_rejected(client):
    assert (await client.get("/api/extensions/export?format=xml")).status_code == 422


async def test_export_requires_auth(anon_client):
    assert (await anon_client.get("/api/extensions/export")).status_code == 401


async def test_export_not_shadowed_by_detail_route(client):
    """/extensions/export must resolve to the export route, not /extensions/{ext_id}."""
    r = await client.get("/api/extensions/export")
    assert r.status_code == 200  # not 422 from int(ext_id="export")


async def test_dashboard_export_links_carry_filters(client, test_db, admin_user):
    async with AsyncSession(test_db) as s:
        await _seed(s, admin_user, [("a" * 32, "edge", "Acme", 80, "Alpha", "[]")])
    r = await client.get("/?store=edge")
    assert r.status_code == 200
    assert "/api/extensions/export?format=csv&amp;store=edge" in r.text
    assert "/api/extensions/export?format=json&amp;store=edge" in r.text
