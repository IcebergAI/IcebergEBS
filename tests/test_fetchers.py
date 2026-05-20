import io
import json
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.fetchers.base import FetchError
from app.fetchers.chrome import ChromeFetcher, _strip_crx_header
from app.fetchers.edge import EdgeFetcher
from app.fetchers.vscode import VSCodeFetcher
from app.routes.api import normalise_extension_id


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def test_normalise_chrome_full_url():
    url = "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
    assert normalise_extension_id("chrome", url) == "cjpalhdlnbpafiamejdnhcphjbkeiagm"


def test_normalise_chrome_bare_id():
    assert normalise_extension_id("chrome", "cjpalhdlnbpafiamejdnhcphjbkeiagm") == "cjpalhdlnbpafiamejdnhcphjbkeiagm"


def test_normalise_vscode_url():
    url = "https://marketplace.visualstudio.com/items?itemName=ms-python.python"
    assert normalise_extension_id("vscode", url) == "ms-python.python"


def test_normalise_vscode_bare_id():
    assert normalise_extension_id("vscode", "ms-python.python") == "ms-python.python"


def test_normalise_edge_url():
    url = "https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak"
    assert normalise_extension_id("edge", url) == "odfafepnkmbhccpbejgmiehpchacaeak"


# ---------------------------------------------------------------------------
# CRX header stripping
# ---------------------------------------------------------------------------

def _make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"manifest_version": 3, "name": "T", "version": "1"}))
    return buf.getvalue()


def test_strip_crx_header():
    zip_bytes = _make_zip()
    fake_crx = b"Cr24" + b"\x00" * 20 + zip_bytes
    result = _strip_crx_header(fake_crx)
    assert result == zip_bytes


def test_strip_crx_no_magic_raises():
    with pytest.raises(FetchError):
        _strip_crx_header(b"not a crx at all")


def test_strip_crx_plain_zip():
    zip_bytes = _make_zip()
    # Plain zip passes through (PK magic at offset 0)
    result = _strip_crx_header(zip_bytes)
    assert result == zip_bytes


# ---------------------------------------------------------------------------
# VS Code fetcher
# ---------------------------------------------------------------------------

VSCODE_API_RESPONSE = {
    "results": [{
        "extensions": [{
            "displayName": "Python",
            "shortDescription": "Python support",
            "publisher": {
                "publisherName": "ms-python",
                "isDomainVerified": True,
            },
            "versions": [{
                "version": "2024.1.0",
                "lastUpdated": "2024-01-15T00:00:00Z",
                "files": [{
                    "assetType": "Microsoft.VisualStudio.Services.VSIXPackage",
                    "source": "https://example.com/fake.vsix",
                }],
            }],
            "statistics": [
                {"statisticName": "install", "value": 50_000_000},
            ],
        }]
    }]
}


@respx.mock
async def test_vscode_fetch_metadata():
    respx.post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery").mock(
        return_value=httpx.Response(200, json=VSCODE_API_RESPONSE)
    )
    async with httpx.AsyncClient() as client:
        fetcher = VSCodeFetcher(client)
        meta = await fetcher.fetch_metadata("ms-python.python")

    assert meta.name == "Python"
    assert meta.publisher == "ms-python"
    assert meta.install_count == 50_000_000
    assert meta.publisher_verified is True
    assert meta.version == "2024.1.0"


@respx.mock
async def test_vscode_fetch_not_found():
    respx.post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery").mock(
        return_value=httpx.Response(200, json={"results": [{"extensions": []}]})
    )
    async with httpx.AsyncClient() as client:
        fetcher = VSCodeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("fake.notexist")


@respx.mock
async def test_vscode_download_package():
    vsix_bytes = _make_zip()
    respx.post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery").mock(
        return_value=httpx.Response(200, json=VSCODE_API_RESPONSE)
    )
    respx.get("https://example.com/fake.vsix").mock(
        return_value=httpx.Response(200, content=vsix_bytes)
    )
    async with httpx.AsyncClient() as client:
        fetcher = VSCodeFetcher(client)
        pkg = await fetcher.download_package("ms-python.python")
    assert pkg == vsix_bytes


# ---------------------------------------------------------------------------
# Chrome fetcher (HTML scraping)
# ---------------------------------------------------------------------------

CHROME_HTML = """
<html><head><meta name="description" content="Block ads"></head>
<body>
<h1>uBlock Origin</h1>
<a data-publisher-id="u123abc" href="./publisher/gorhill/u123abc">gorhill</a>
<div>
  <div>Offered by</div>
  <div>gorhill (fallback)</div>
</div>
<div>
  <div>Updated</div>
  <div>January 10, 2024</div>
</div>
<div>Version: 1.54.0</div>
<div>10,000,000 users</div>
</body></html>
"""

CHROME_HTML_MDSAPD = """
<html><head><meta name="description" content="Threat intelligence"></head>
<body>
<h1>Recorded Future</h1>
<div class="mdSapd">Recorded Future<br/>363 Highland Avenue
Suite 2
Somerville MA 02144
USA</div>
<div>
  <div>Updated</div>
  <div>January 10, 2024</div>
</div>
<div>Version: 1.54.0</div>
<div>10,000,000 users</div>
</body></html>
"""

CHROME_HTML_NO_PUBLISHER_LINK = """
<html><head><meta name="description" content="Block ads"></head>
<body>
<h1>uBlock Origin</h1>
<div>
  <div>Offered by</div>
  <div>gorhill</div>
</div>
<div>
  <div>Updated</div>
  <div>January 10, 2024</div>
</div>
<div>Version: 1.54.0</div>
<div>10,000,000 users</div>
</body></html>
"""


@respx.mock
async def test_chrome_fetch_metadata():
    """Publisher comes from the data-publisher-id link, not the Offered by fallback."""
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.name == "uBlock Origin"
    assert meta.publisher == "gorhill"  # from data-publisher-id link, not "gorhill (fallback)"
    assert meta.install_count == 10_000_000
    assert meta.last_updated is not None
    assert meta.last_updated.year == 2024
    assert meta.last_updated.month == 1
    assert meta.last_updated.day == 10


@respx.mock
async def test_chrome_fetch_metadata_mdsapd_publisher():
    """Falls back to div.mdSapd first text node when no data-publisher-id link."""
    respx.get("https://chromewebstore.google.com/detail/cdblaggcibgbankgilackljdpdhhcine").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_MDSAPD)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cdblaggcibgbankgilackljdpdhhcine")
    assert meta.publisher == "Recorded Future"


@respx.mock
async def test_chrome_fetch_metadata_publisher_fallback():
    """Falls back to Offered by text when neither data-publisher-id nor mdSapd present."""
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_NO_PUBLISHER_LINK)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.publisher == "gorhill"


@respx.mock
async def test_chrome_fetch_404():
    respx.get("https://chromewebstore.google.com/detail/doesnotexist").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("doesnotexist")


@respx.mock
async def test_chrome_download_package_preserves_raw_crx_bytes():
    zip_bytes = _make_zip()
    raw_crx = b"Cr24" + b"\x00" * 20 + zip_bytes
    respx.get(url__regex=r".*clients2\.google\.com/service/update2/crx.*").mock(
        return_value=httpx.Response(200, content=raw_crx)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        pkg = await fetcher.download_package("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert pkg == raw_crx


@respx.mock
async def test_package_download_rejects_large_content_length():
    respx.get("https://example.com/large.vsix").mock(
        return_value=httpx.Response(200, headers={"content-length": str(65 * 1024 * 1024)})
    )
    async with httpx.AsyncClient() as client:
        fetcher = VSCodeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher._get_package_bytes("https://example.com/large.vsix")


@respx.mock
async def test_package_download_rejects_stream_over_limit():
    respx.get("https://example.com/large.vsix").mock(
        return_value=httpx.Response(200, content=b"x" * (65 * 1024 * 1024))
    )
    async with httpx.AsyncClient() as client:
        fetcher = VSCodeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher._get_package_bytes("https://example.com/large.vsix")


# ---------------------------------------------------------------------------
# Edge fetcher — uses the getproductdetailsbycrxid JSON API
# ---------------------------------------------------------------------------

import json as _json
import zipfile as _zipfile

_EDGE_API_BASE = "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid"
_EDGE_CRX_BASE = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

_FAKE_MANIFEST = {
    "manifest_version": 3,
    "name": "Bitwarden Password Manager",
    "version": "2024.1.0",
    "permissions": ["storage", "tabs"],
    "host_permissions": ["https://*/*"],
}

EDGE_API_RESPONSE = {
    "name": "Bitwarden Password Manager",
    "developer": "Bitwarden Inc.",
    "version": "2024.1.0",
    "activeInstallCount": 2_703_365,
    "lastUpdateDate": 1704067200.0,  # 2024-01-01 00:00:00 UTC
    "description": "A secure password manager.",
    "shortDescription": "Password manager",
    "manifest": _json.dumps(_FAKE_MANIFEST),
    "crxId": "testid",
}


@respx.mock
async def test_edge_fetch_metadata():
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(
        return_value=httpx.Response(200, json=EDGE_API_RESPONSE)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta = await fetcher.fetch_metadata("testid")
    assert meta.name == "Bitwarden Password Manager"
    assert meta.publisher == "Bitwarden Inc."
    assert meta.version == "2024.1.0"
    assert meta.install_count == 2_703_365
    assert meta.last_updated is not None
    assert meta.last_updated.year == 2024
    assert meta.last_updated.month == 1
    assert meta.last_updated.day == 1
    assert meta.description == "A secure password manager."


@respx.mock
async def test_edge_fetch_uses_manifest_when_crx_unavailable():
    """When the CRX download fails, permissions still come from the API manifest."""
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(
        return_value=httpx.Response(200, json=EDGE_API_RESPONSE)
    )
    respx.get(url__regex=r".*extensionwebstorebase.*").mock(
        return_value=httpx.Response(405)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta, pkg_bytes = await fetcher.fetch("testid")

    assert meta.name == "Bitwarden Password Manager"
    assert pkg_bytes is not None
    # Verify the fallback zip contains the manifest with permissions
    with _zipfile.ZipFile(io.BytesIO(pkg_bytes)) as zf:
        manifest = _json.loads(zf.read("manifest.json"))
    assert manifest["permissions"] == ["storage", "tabs"]
    assert manifest["host_permissions"] == ["https://*/*"]


@respx.mock
async def test_edge_fetch_upgrades_to_crx_when_available():
    """When the CRX download succeeds, the full package is returned instead of manifest-only zip."""
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(
        return_value=httpx.Response(200, json=EDGE_API_RESPONSE)
    )
    crx_zip = _make_zip()
    raw_crx = b"Cr24" + b"\x00" * 20 + crx_zip
    respx.get(url__regex=r".*extensionwebstorebase.*").mock(
        return_value=httpx.Response(200, content=raw_crx)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta, pkg_bytes = await fetcher.fetch("testid")

    assert pkg_bytes == raw_crx  # got the real package, not the manifest fallback


@respx.mock
async def test_edge_fetch_metadata_missing_optional_fields():
    """API response with only required fields — optional fields default gracefully."""
    respx.get(f"{_EDGE_API_BASE}/minimalid?hl=en-US").mock(
        return_value=httpx.Response(200, json={"name": "Minimal Ext", "crxId": "minimalid"})
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta = await fetcher.fetch_metadata("minimalid")
    assert meta.name == "Minimal Ext"
    assert meta.publisher == ""
    assert meta.version == ""
    assert meta.install_count is None
    assert meta.last_updated is None


@respx.mock
async def test_edge_fetch_404():
    respx.get(f"{_EDGE_API_BASE}/doesnotexist?hl=en-US").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("doesnotexist")
