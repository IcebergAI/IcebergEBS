"""Bulk import POST /api/extensions/bulk (#24)."""

from unittest.mock import AsyncMock, patch

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import FetchError
from app.models import Extension
from tests.test_api import _fake_metadata, _fake_vsix


def _mock_vscode():
    p = patch("app.fetchers.VSCodeFetcher")
    MockFetcher = p.start()
    MockFetcher.return_value.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
    return p


async def test_bulk_mixed_batch(client, test_db, admin_user):
    # Pre-existing extension to exercise the dedupe path.
    async with AsyncSession(test_db) as s:
        s.add(
            Extension(
                user_id=admin_user.id,
                store="vscode",
                extension_id="dup.ext",
                name="Dup",
                publisher="p",
                version="1.0",
                store_url="https://example.com",
            )
        )
        await s.commit()

    p = _mock_vscode()
    try:
        r = await client.post(
            "/api/extensions/bulk",
            json={
                "items": [
                    {"store": "vscode", "extension_id": "newpub.new-ext"},
                    {"store": "vscode", "extension_id": "dup.ext"},
                    {"store": "vscode", "extension_id": "not a valid id"},
                ]
            },
        )
    finally:
        p.stop()

    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 1
    assert body["duplicates"] == 1
    assert body["invalid"] == 1
    assert body["errors"] == 0
    by_id = {res["extension_id"]: res for res in body["results"]}
    assert by_id["newpub.new-ext"]["status"] == "added"
    assert by_id["newpub.new-ext"]["id"] is not None
    assert by_id["dup.ext"]["status"] == "duplicate"
    assert by_id["not a valid id"]["status"] == "invalid"


async def test_bulk_text_paste(client):
    p = _mock_vscode()
    try:
        r = await client.post(
            "/api/extensions/bulk",
            json={"text": ("vscode,textpub.ext\n# a comment line, ignored\n\ngarbage-with-no-store\n")},
        )
    finally:
        p.stop()

    body = r.json()
    assert body["added"] == 1
    assert body["invalid"] == 1
    statuses = {res["extension_id"]: res["status"] for res in body["results"]}
    assert statuses["textpub.ext"] == "added"
    assert statuses["garbage-with-no-store"] == "invalid"


async def test_bulk_fetch_error_leaves_no_row(client, test_db):
    p = patch("app.fetchers.VSCodeFetcher")
    MockFetcher = p.start()
    MockFetcher.return_value.fetch = AsyncMock(side_effect=FetchError("boom"))
    try:
        r = await client.post(
            "/api/extensions/bulk",
            json={
                "items": [
                    {"store": "vscode", "extension_id": "ghostpub.ghost"},
                ]
            },
        )
    finally:
        p.stop()

    body = r.json()
    assert body["errors"] == 1
    assert body["results"][0]["status"] == "error"
    # No placeholder row left behind.
    async with AsyncSession(test_db) as s:
        rows = (await s.exec(select(Extension).where(Extension.extension_id == "ghostpub.ghost"))).all()
        assert rows == []


async def test_bulk_empty_rejected(client):
    assert (await client.post("/api/extensions/bulk", json={})).status_code == 422


async def test_bulk_too_many_rejected(client):
    items = [{"store": "vscode", "extension_id": f"pub.ext{i}"} for i in range(101)]
    r = await client.post("/api/extensions/bulk", json={"items": items})
    assert r.status_code == 422


async def test_bulk_requires_auth(anon_client):
    r = await anon_client.post(
        "/api/extensions/bulk",
        json={
            "items": [
                {"store": "vscode", "extension_id": "pub.ext"},
            ]
        },
    )
    assert r.status_code == 401


async def test_bulk_url_autodetect(client):
    p = _mock_vscode()
    try:
        r = await client.post(
            "/api/extensions/bulk",
            json={"text": ("https://marketplace.visualstudio.com/items?itemName=urlpub.urlext\n")},
        )
    finally:
        p.stop()
    body = r.json()
    assert body["added"] == 1
    assert body["results"][0]["store"] == "vscode"
    assert body["results"][0]["extension_id"] == "urlpub.urlext"


async def test_bulk_import_page_renders(client):
    r = await client.get("/extensions/bulk")
    assert r.status_code == 200
    assert "Bulk import" in r.text
    # The API wiring lives in the external page script since #106 (no inline
    # scripts under the strict CSP) — the page must load it.
    assert "/static/js/pages/bulk-import.js" in r.text


async def test_bulk_import_page_requires_auth(anon_client):
    r = await anon_client.get("/extensions/bulk", follow_redirects=False)
    assert r.status_code in (302, 303, 307)
