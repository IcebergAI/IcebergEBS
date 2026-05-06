from datetime import datetime, timezone

import httpx

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
