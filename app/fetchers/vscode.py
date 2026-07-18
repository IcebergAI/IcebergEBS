import logging
from datetime import datetime

import httpx

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

logger = logging.getLogger(__name__)

_GALLERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_FLAGS = 914  # includes statistics, versions, publisher, file list
_HEADERS = {
    "Accept": "application/json;api-version=7.1-preview.1",
    "Content-Type": "application/json",
}


class VSCodeFetcher(BaseFetcher):
    async def _call_gallery(self, extension_id: str) -> dict:
        payload = {
            "filters": [{"criteria": [{"filterType": 7, "value": extension_id}]}],
            "flags": _FLAGS,
        }
        # The gallery query is a read served over POST — opt it into RetryTransport's
        # retries so a transient 429/5xx is retried like a GET (#108). Webhook POSTs
        # don't set this, so they're still never retried.
        resp = await self.client.post(
            _GALLERY_URL, json=payload, headers=_HEADERS, extensions={"retry_idempotent": True}
        )
        if resp.status_code != 200:
            raise FetchError(f"Marketplace API returned {resp.status_code}")
        data = resp.json()
        try:
            return data["results"][0]["extensions"][0]
        except (KeyError, IndexError) as exc:
            raise FetchError(f"Extension not found: {extension_id}") from exc

    def _parse_metadata(self, ext: dict, extension_id: str) -> ExtensionMetadata:
        publisher = ext.get("publisher", {})
        versions = ext.get("versions", [{}])
        latest = versions[0] if versions else {}

        install_count = None
        for stat in ext.get("statistics", []):
            if stat.get("statisticName") == "install":
                install_count = int(stat.get("value", 0))
                break

        last_updated = None
        if raw_date := latest.get("lastUpdated"):
            try:
                last_updated = datetime.fromisoformat(raw_date)
            except ValueError:
                pass

        return ExtensionMetadata(
            name=ext.get("displayName") or extension_id,
            publisher=publisher.get("publisherName", ""),
            description=ext.get("shortDescription"),
            version=latest.get("version", ""),
            install_count=install_count,
            last_updated=last_updated,
            store_url=f"https://marketplace.visualstudio.com/items?itemName={extension_id}",
            publisher_verified=publisher.get("isDomainVerified"),
        )

    def _vsix_url(self, ext: dict, extension_id: str) -> str:
        versions = ext.get("versions", [{}])
        files = (versions[0] if versions else {}).get("files", [])
        for f in files:
            if f.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage":
                url = f.get("source")
                if url:
                    return url
        raise FetchError(f"No VSIX asset found for {extension_id}")

    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        return self._parse_metadata(await self._call_gallery(extension_id), extension_id)

    async def download_package(self, extension_id: str) -> bytes:
        ext = await self._call_gallery(extension_id)
        vsix_url = self._vsix_url(ext, extension_id)
        return await self._get_package_bytes(vsix_url)

    async def fetch(self, extension_id: str) -> tuple[ExtensionMetadata, bytes | None]:
        """Single API call returning both metadata and package."""
        ext = await self._call_gallery(extension_id)
        metadata = self._parse_metadata(ext, extension_id)
        try:
            vsix_url = self._vsix_url(ext, extension_id)
            package: bytes | None = await self._get_package_bytes(vsix_url)
        except (FetchError, httpx.HTTPError) as exc:
            # Non-fatal: metadata already parsed. Narrow to network/HTTP errors so
            # a programming bug surfaces instead of silently skipping analysis (M5).
            logger.warning(
                "VS Code VSIX download failed for %s (%s) — JS analysis skipped",
                extension_id,
                exc,
            )
            package = None
        return metadata, package
