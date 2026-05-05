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
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.name == "uBlock Origin"
    assert meta.publisher == "gorhill"
    assert meta.install_count == 10_000_000
    assert meta.last_updated is not None
    assert meta.last_updated.year == 2024
    assert meta.last_updated.month == 1
    assert meta.last_updated.day == 10


@respx.mock
async def test_chrome_fetch_404():
    respx.get("https://chromewebstore.google.com/detail/doesnotexist").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("doesnotexist")


# ---------------------------------------------------------------------------
# Edge fetcher (HTML scraping)
# ---------------------------------------------------------------------------

EDGE_HTML = """
<html>
<head>
  <meta name="description" content="Block ads">
  <meta property="og:title" content="uBlock Origin">
  <title>uBlock Origin - Microsoft Edge Addons</title>
</head>
<body>
<h1>Some nav heading</h1>
<dl>
  <dt>Offered by</dt><dd>Raymond Hill</dd>
  <dt>Version</dt><dd>1.54.0</dd>
  <dt>Users</dt><dd>5,000,000</dd>
  <dt>Last updated</dt><dd>January 10, 2024</dd>
</dl>
</body></html>
"""

EDGE_HTML_UPDATED_LABEL = """
<html>
<head>
  <title>Test Extension - Microsoft Edge Addons</title>
</head>
<body>
<dl>
  <dt>Developer</dt><dd>Some Dev</dd>
  <dt>Version</dt><dd>2.0.0</dd>
  <dt>Users</dt><dd>1,000</dd>
  <dt>Updated</dt><dd>01/10/2024</dd>
</dl>
</body></html>
"""


@respx.mock
async def test_edge_fetch_metadata():
    respx.get("https://microsoftedge.microsoft.com/addons/detail/testid").mock(
        return_value=httpx.Response(200, text=EDGE_HTML)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta = await fetcher.fetch_metadata("testid")
    # Name should come from og:title, not the nav <h1>
    assert meta.name == "uBlock Origin"
    assert meta.publisher == "Raymond Hill"
    assert meta.version == "1.54.0"
    assert meta.install_count == 5_000_000
    assert meta.last_updated is not None
    assert meta.last_updated.year == 2024
    assert meta.last_updated.month == 1
    assert meta.last_updated.day == 10


@respx.mock
async def test_edge_fetch_metadata_updated_label_and_mmddyyyy():
    """Edge sometimes uses 'Updated' label and MM/DD/YYYY date format."""
    respx.get("https://microsoftedge.microsoft.com/addons/detail/testid2").mock(
        return_value=httpx.Response(200, text=EDGE_HTML_UPDATED_LABEL)
    )
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        meta = await fetcher.fetch_metadata("testid2")
    # Name should fall back to <title> stripping the suffix
    assert meta.name == "Test Extension"
    assert meta.last_updated is not None
    assert meta.last_updated.year == 2024
    assert meta.last_updated.month == 1
    assert meta.last_updated.day == 10
