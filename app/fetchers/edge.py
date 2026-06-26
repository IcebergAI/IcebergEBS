import io
import logging
import zipfile
from datetime import datetime, timezone

import httpx

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

logger = logging.getLogger(__name__)

_API_URL = "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}?hl=en-US"
_DETAIL_URL = "https://microsoftedge.microsoft.com/addons/detail/{extension_id}"
_DOWNLOAD_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?x=id%3D{extension_id}%26installsource%3Dondemand&response=redirect"
)


def _manifest_to_zip(manifest_str: str) -> bytes:
    """Wrap a raw manifest JSON string in a minimal zip for the inspector."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_str)
    return buf.getvalue()


class EdgeFetcher(BaseFetcher):
    async def _call_api(self, extension_id: str) -> dict:
        """GET the product-details API and return the parsed JSON body.

        Shared by ``fetch_metadata`` and ``fetch`` so the request + status-check +
        error handling live in one place (D5 / #15).
        """
        url = _API_URL.format(extension_id=extension_id)
        logger.debug("Edge API request: %s", url)
        resp = await self.client.get(url, follow_redirects=True)
        logger.debug("Edge API response: %s", resp.status_code)
        if resp.status_code == 404:
            raise FetchError(f"Extension not found: {extension_id}")
        if resp.status_code != 200:
            raise FetchError(f"Edge Add-ons API returned {resp.status_code}")
        return resp.json()

    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        return _parse_response(await self._call_api(extension_id), extension_id)

    async def download_package(self, extension_id: str) -> bytes:
        url = _DOWNLOAD_URL.format(extension_id=extension_id)
        logger.debug("Edge CRX download: %s", url)
        content = await self._get_package_bytes(url)
        logger.debug("Edge CRX downloaded: size=%d", len(content))
        return content

    async def fetch(self, extension_id: str) -> tuple[ExtensionMetadata, bytes | None]:
        """Single API call for metadata; manifest from the response guarantees permissions
        are always available. Attempts a full CRX download for JS static analysis —
        falls back to the manifest-only package if the download fails.
        """
        data = await self._call_api(extension_id)
        metadata = _parse_response(data, extension_id)
        logger.info(
            "Edge metadata fetched: %s v%s by %s, installs=%s",
            metadata.name,
            metadata.version,
            metadata.publisher,
            metadata.install_count,
        )

        manifest_str = data.get("manifest", "")
        if manifest_str:
            pkg_bytes: bytes | None = _manifest_to_zip(manifest_str)
            logger.debug("Edge manifest-only package built (%d bytes)", len(pkg_bytes))
        else:
            pkg_bytes = None
            logger.warning("Edge API response for %s contained no manifest field", extension_id)

        try:
            pkg_bytes = await self.download_package(extension_id)
            logger.info("Edge CRX downloaded for %s (%d bytes)", extension_id, len(pkg_bytes))
        except (FetchError, httpx.HTTPError) as exc:
            # edge.microsoft.com/extensionwebstorebase currently returns HTTP 500 for all
            # GET requests regardless of User-Agent or query parameters — server-side fault.
            # Permissions are still available from the manifest embedded in the API response.
            # Narrowed to network/HTTP errors so a genuine bug propagates instead of
            # being swallowed behind the manifest-only fallback (M5 / #10).
            logger.warning(
                "Edge CRX unavailable for %s (%s) — JS analysis skipped, using manifest-only package",
                extension_id,
                exc,
            )

        return metadata, pkg_bytes


def _parse_response(data: dict, extension_id: str) -> ExtensionMetadata:
    last_updated = None
    raw_ts = data.get("lastUpdateDate")
    if raw_ts is not None:
        try:
            last_updated = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
        except (ValueError, OSError):
            pass

    return ExtensionMetadata(
        name=data.get("name") or extension_id,
        publisher=data.get("developer") or "",
        description=data.get("description") or data.get("shortDescription"),
        version=data.get("version") or "",
        install_count=data.get("activeInstallCount"),
        last_updated=last_updated,
        store_url=_DETAIL_URL.format(extension_id=extension_id),
    )
