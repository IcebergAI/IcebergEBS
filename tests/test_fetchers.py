import io
import json

import httpx
import pytest
import respx

from app.fetchers.base import FetchError
from app.fetchers.chrome import ChromeFetcher
from app.fetchers.edge import EdgeFetcher
from app.fetchers.vscode import VSCodeFetcher
from app.routes.api import normalise_extension_id
from tests.conftest import make_zip

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
    return make_zip({"manifest.json": json.dumps({"manifest_version": 3, "name": "T", "version": "1"})})


# ---------------------------------------------------------------------------
# VS Code fetcher
# ---------------------------------------------------------------------------

VSCODE_API_RESPONSE = {
    "results": [
        {
            "extensions": [
                {
                    "displayName": "Python",
                    "shortDescription": "Python support",
                    "publisher": {
                        "publisherName": "ms-python",
                        "isDomainVerified": True,
                    },
                    "versions": [
                        {
                            "version": "2024.1.0",
                            "lastUpdated": "2024-01-15T00:00:00Z",
                            "files": [
                                {
                                    "assetType": "Microsoft.VisualStudio.Services.VSIXPackage",
                                    "source": "https://example.com/fake.vsix",
                                }
                            ],
                        }
                    ],
                    "statistics": [
                        {"statisticName": "install", "value": 50_000_000},
                    ],
                }
            ]
        }
    ]
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
    respx.get("https://example.com/fake.vsix").mock(return_value=httpx.Response(200, content=vsix_bytes))
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
    respx.get("https://chromewebstore.google.com/detail/doesnotexist").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("doesnotexist")


CHROME_HTML_HIJACK = """
<html><head>
<meta name="description" content="Join 1,000,000 users today! New in Version 9.9.9">
<title>Ext</title>
</head>
<body>
<h1>Ext</h1>
<script>var data = {"description": "Join 1,000,000 users today! New in Version 9.9.9"};</script>
<div>Version: 1.2.3</div>
<div>10,000 users</div>
</body></html>
"""

CHROME_HTML_HIJACK_ONLY = """
<html><head>
<meta name="description" content="Join 1,000,000 users today! New in Version 9.9.9">
</head>
<body>
<h1>Ext</h1>
<script>var data = {"description": "Join 1,000,000 users today! New in Version 9.9.9"};</script>
</body></html>
"""

CHROME_HTML_NO_HEAD = """
<body>
<h1>Ext</h1>
<div>Version: 1.2.3</div>
<div>10,000 users</div>
</body>
"""


@respx.mock
async def test_chrome_count_and_version_ignore_head_and_script_text():
    """The description meta (head) and script JSON blobs repeat the description;
    the first-match regexes must only see visible page text (#142)."""
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_HIJACK)
    )
    async with httpx.AsyncClient() as client:
        meta = await ChromeFetcher(client).fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.install_count == 10_000
    assert meta.version == "1.2.3"
    assert meta.description == "Join 1,000,000 users today! New in Version 9.9.9"


@respx.mock
async def test_chrome_count_and_version_absent_when_only_in_metadata():
    """Strings appearing only in the meta description / script blobs must not
    be mistaken for the real values (#142)."""
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_HIJACK_ONLY)
    )
    async with httpx.AsyncClient() as client:
        meta = await ChromeFetcher(client).fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.install_count is None
    assert meta.version == ""


@respx.mock
async def test_chrome_parse_degrades_without_head():
    """A document with no <head>/<script> still yields the body values."""
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_NO_HEAD)
    )
    async with httpx.AsyncClient() as client:
        meta = await ChromeFetcher(client).fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.install_count == 10_000
    assert meta.version == "1.2.3"


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
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(return_value=httpx.Response(200, json=EDGE_API_RESPONSE))
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
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(return_value=httpx.Response(200, json=EDGE_API_RESPONSE))
    respx.get(url__regex=r".*extensionwebstorebase.*").mock(return_value=httpx.Response(405))
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
    respx.get(f"{_EDGE_API_BASE}/testid?hl=en-US").mock(return_value=httpx.Response(200, json=EDGE_API_RESPONSE))
    crx_zip = _make_zip()
    raw_crx = b"Cr24" + b"\x00" * 20 + crx_zip
    respx.get(url__regex=r".*extensionwebstorebase.*").mock(return_value=httpx.Response(200, content=raw_crx))
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
    respx.get(f"{_EDGE_API_BASE}/doesnotexist?hl=en-US").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        fetcher = EdgeFetcher(client)
        with pytest.raises(FetchError):
            await fetcher.fetch_metadata("doesnotexist")


@respx.mock
async def test_package_download_failure_log_is_scrubbed(caplog):
    # The best-effort package paths log the raw exception; a proxy-layer failure can
    # echo the credential-injected proxy URL there (#228 review).
    import logging
    from unittest.mock import AsyncMock, patch

    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        leaky = httpx.ProxyError("CONNECT via http://bob:hunter2@proxy.corp:3128 refused")
        with patch.object(fetcher, "download_package", AsyncMock(side_effect=leaky)):
            with caplog.at_level(logging.WARNING):
                metadata, package = await fetcher.fetch("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert package is None
    assert "hunter2" not in caplog.text
    assert "bob:" not in caplog.text
    assert "proxy.corp" in caplog.text  # only the userinfo is redacted


CHROME_HTML_VERSION_IN_DESCRIPTION = """
<html><head><meta name="description" content="Best ad blocker"></head>
<body>
<h1>uBlock Origin</h1>
<p>What's new: see our changelog. New in Version 9.9.9 we improved everything!</p>
<div>
  <div>Offered by</div>
  <div>gorhill</div>
</div>
<div>
  <div>Updated</div>
  <div>January 10, 2024</div>
</div>
<div>
  <div>Version</div>
  <div>1.54.0</div>
</div>
<div>10,000,000 users</div>
</body></html>
"""


@respx.mock
async def test_chrome_version_not_hijacked_by_description_text():
    # The description renders as visible body text BEFORE the details section; the
    # old whole-page regex took its "New in Version 9.9.9" as the version on every
    # fetch — one spurious new_version alert, then a permanently wrong stored
    # version (#279). Label adjacency in the details section must win.
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_VERSION_IN_DESCRIPTION)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.version == "1.54.0"


@respx.mock
async def test_chrome_version_regex_fallback_still_works():
    # Pages carrying only the inline "Version: x.y.z" form (no label/value split)
    # keep working through the fallback regex (#279).
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_NO_PUBLISHER_LINK)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.version == "1.54.0"


CHROME_HTML_DESCRIPTION_PROSE_AND_INLINE_VERSION = """
<html><head><meta name="description" content="Best ad blocker"></head>
<body>
<h1>uBlock Origin</h1>
<p>What's new — Version: 9.9.9 improves everything!</p>
<div>10,000,000 users</div>
<p>Version: 1.54.0</p>
</body></html>
"""


@respx.mock
async def test_chrome_inline_version_fallback_not_hijacked_by_description_prose():
    # The combined case (#279 review): no Details label/value split, so exact-label
    # extraction returns empty and the inline fallback runs — but a colon-bearing
    # description sentence "Version: 9.9.9 improves everything" precedes the real
    # "Version: 1.54.0". Anchored per-node matching means the embedding sentence can't
    # win: only the standalone "Version: 1.54.0" node matches.
    respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML_DESCRIPTION_PROSE_AND_INLINE_VERSION)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        meta = await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    assert meta.version == "1.54.0"


@respx.mock
async def test_chrome_fetch_pins_english_locale():
    # No locale pin meant Google localized by egress IP: "Aktualisiert" labels and
    # German dates → last_updated=None forever → staleness silently scored 10 for a
    # fresh extension on any non-US deployment (#279). The request must carry hl=en
    # and an Accept-Language header, like the Edge fetcher's hl pin.
    route = respx.get("https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm").mock(
        return_value=httpx.Response(200, text=CHROME_HTML)
    )
    async with httpx.AsyncClient() as client:
        fetcher = ChromeFetcher(client)
        await fetcher.fetch_metadata("cjpalhdlnbpafiamejdnhcphjbkeiagm")
    request = route.calls.last.request
    assert request.url.params["hl"] == "en"
    assert request.headers["Accept-Language"] == "en-US,en"
