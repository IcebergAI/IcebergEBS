from datetime import datetime, timezone

import httpx

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

_GALLERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_FLAGS = 914  # includes statistics, versions, publisher, file list


class VSCodeFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        """extension_id format: publisher.extensionName"""
        payload = {
            "filters": [{"criteria": [{"filterType": 7, "value": extension_id}]}],
            "flags": _FLAGS,
        }
        resp = await self.client.post(
            _GALLERY_URL,
            json=payload,
            headers={
                "Accept": "application/json;api-version=7.1-preview.1",
                "Content-Type": "application/json",
            },
        )
        if resp.status_code != 200:
            raise FetchError(f"Marketplace API returned {resp.status_code}")

        data = resp.json()
        try:
            ext = data["results"][0]["extensions"][0]
        except (KeyError, IndexError):
            raise FetchError(f"Extension not found: {extension_id}")

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
                last_updated = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
            except ValueError:
                pass

        store_url = (
            f"https://marketplace.visualstudio.com/items?itemName={extension_id}"
        )

        return ExtensionMetadata(
            name=ext.get("displayName") or extension_id,
            publisher=publisher.get("publisherName", ""),
            description=ext.get("shortDescription"),
            version=latest.get("version", ""),
            install_count=install_count,
            last_updated=last_updated,
            store_url=store_url,
            publisher_verified=publisher.get("isDomainVerified"),
        )

    async def download_package(self, extension_id: str) -> bytes:
        """Download .vsix package via the gallery asset endpoint."""
        publisher, name = extension_id.split(".", 1)
        # Fetch the asset URL from the API first
        payload = {
            "filters": [{"criteria": [{"filterType": 7, "value": extension_id}]}],
            "flags": _FLAGS,
        }
        resp = await self.client.post(
            _GALLERY_URL,
            json=payload,
            headers={
                "Accept": "application/json;api-version=7.1-preview.1",
                "Content-Type": "application/json",
            },
        )
        if resp.status_code != 200:
            raise FetchError(f"Marketplace API returned {resp.status_code}")

        data = resp.json()
        try:
            files = data["results"][0]["extensions"][0]["versions"][0]["files"]
        except (KeyError, IndexError):
            raise FetchError(f"No version files for {extension_id}")

        vsix_url = None
        for f in files:
            if f.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage":
                vsix_url = f.get("source")
                break

        if not vsix_url:
            raise FetchError(f"No VSIX asset found for {extension_id}")

        pkg_resp = await self.client.get(vsix_url, follow_redirects=True)
        if pkg_resp.status_code != 200:
            raise FetchError(f"VSIX download returned {pkg_resp.status_code}")

        return pkg_resp.content
