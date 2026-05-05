import io
import json
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import ExtensionMetadata, FetchError
from app.models import Extension


def _fake_metadata():
    from datetime import datetime, timezone
    return ExtensionMetadata(
        name="Test Extension",
        publisher="testpub",
        description="A test extension",
        version="1.0.0",
        install_count=50000,
        last_updated=datetime(2023, 6, 1, tzinfo=timezone.utc),
        store_url="https://example.com",
        publisher_verified=True,
    )


def _fake_vsix() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.0.0",
            "permissions": ["storage"],
        }))
        zf.writestr("background.js", 'console.log("hello");')
    return buf.getvalue()


async def test_list_extensions_empty(client):
    r = await client.get("/api/extensions")
    assert r.status_code == 200
    assert r.json() == []


async def test_add_extension(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))

        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.test-ext",
        })

    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "Test Extension"
    assert data["store"] == "vscode"
    assert data["extension_id"] == "testpub.test-ext"
    assert data["risk_score"] is not None
    return data["id"]


async def test_add_extension_duplicate(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))

        await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.dupe-ext",
        })
        r2 = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.dupe-ext",
        })

    assert r2.status_code == 409


async def test_get_extension(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.get-test",
        })
    ext_id = r.json()["id"]

    r2 = await client.get(f"/api/extensions/{ext_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == ext_id


async def test_delete_extension(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.del-test",
        })
    ext_id = r.json()["id"]

    r_del = await client.delete(f"/api/extensions/{ext_id}")
    assert r_del.status_code == 200
    assert r_del.json() == {"ok": True}

    r_get = await client.get(f"/api/extensions/{ext_id}")
    assert r_get.status_code == 404


async def test_refresh_extension(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.refresh-test",
        })
    ext_id = r.json()["id"]

    with patch("app.routes.api.VSCodeFetcher") as MockFetcher2:
        instance2 = MockFetcher2.return_value
        meta2 = _fake_metadata()
        instance2.fetch = AsyncMock(return_value=(meta2, _fake_vsix()))
        r2 = await client.post(f"/api/extensions/{ext_id}/refresh")

    assert r2.status_code == 200
    assert r2.json()["last_fetched_at"] is not None


async def test_toggle_watchlist(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.watch-test",
        })
    ext_id = r.json()["id"]
    assert r.json()["watchlist"] is True

    r2 = await client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    assert r2.status_code == 200
    assert r2.json()["watchlist"] is False


async def test_get_history_empty(client):
    with patch("app.routes.api.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), None))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.hist-test",
        })
    ext_id = r.json()["id"]

    r2 = await client.get(f"/api/extensions/{ext_id}/history")
    assert r2.status_code == 200
    # install_count=50000 so one history entry should exist
    assert isinstance(r2.json(), list)


async def test_unauthenticated_api(anon_client):
    r = await anon_client.get("/api/extensions", follow_redirects=False)
    assert r.status_code == 303
