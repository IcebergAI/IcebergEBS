import io
import zipfile
from datetime import datetime, timezone

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

_API_URL = (
    "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid"
    "/{extension_id}?hl=en-US"
)
_DETAIL_URL = "https://microsoftedge.microsoft.com/addons/detail/{extension_id}"
_DOWNLOAD_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?response=redirect&x=id%3D{extension_id}%26uc"
)
_CRX_MAGIC = b"PK\x03\x04"


def _strip_crx_header(data: bytes) -> bytes:
    offset = data.find(_CRX_MAGIC)
    if offset == -1:
        raise FetchError("Not a valid CRX file: no zip signature found")
    return data[offset:]


def _manifest_to_zip(manifest_str: str) -> bytes:
    """Wrap a raw manifest JSON string in a minimal zip for the inspector."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_str)
    return buf.getvalue()


class EdgeFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        url = _API_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code == 404:
            raise FetchError(f"Extension not found: {extension_id}")
        if resp.status_code != 200:
            raise FetchError(f"Edge Add-ons API returned {resp.status_code}")
        return _parse_response(resp.json(), extension_id)

    async def download_package(self, extension_id: str) -> bytes:
        url = _DOWNLOAD_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code != 200:
            raise FetchError(f"CRX download returned {resp.status_code}")
        return _strip_crx_header(resp.content)

    async def fetch(self, extension_id: str) -> tuple[ExtensionMetadata, bytes | None]:
        """Single API call for metadata; manifest from the response guarantees permissions
        are always available. Attempts a full CRX download for JS static analysis —
        falls back to the manifest-only package if the download fails.
        """
        url = _API_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code == 404:
            raise FetchError(f"Extension not found: {extension_id}")
        if resp.status_code != 200:
            raise FetchError(f"Edge Add-ons API returned {resp.status_code}")

        data = resp.json()
        metadata = _parse_response(data, extension_id)

        # Use the manifest embedded in the API response as a guaranteed baseline.
        # This ensures permissions and host_permissions are always extracted even
        # if the CRX download endpoint is unavailable.
        manifest_str = data.get("manifest", "")
        pkg_bytes: bytes | None = _manifest_to_zip(manifest_str) if manifest_str else None

        # Attempt a full CRX download for deeper JS analysis (eval detection,
        # obfuscation scoring, external domain scanning). Silently fall back to
        # the manifest-only package on failure.
        try:
            pkg_bytes = await self.download_package(extension_id)
        except Exception:
            pass

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
