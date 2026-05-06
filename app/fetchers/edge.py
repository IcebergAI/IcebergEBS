import httpx
from bs4 import BeautifulSoup

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

_DETAIL_URL = "https://microsoftedge.microsoft.com/addons/detail/{extension_id}"
_DOWNLOAD_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?response=redirect&x=id%3D{extension_id}%26uc"
)
_CRX_MAGIC = b"PK\x03\x04"

# Suffixes that appear in the Edge Add-ons <title> tag
_TITLE_SUFFIXES = (
    " - Microsoft Edge Add-ons",
    " – Microsoft Edge Add-ons",
    " | Microsoft Edge Add-ons",
    " - Microsoft Edge Addons",
    " – Microsoft Edge Addons",
    " | Microsoft Edge Addons",
)


def _strip_crx_header(data: bytes) -> bytes:
    offset = data.find(_CRX_MAGIC)
    if offset == -1:
        raise FetchError("Not a valid CRX file: no zip signature found")
    return data[offset:]


class EdgeFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        url = _DETAIL_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code == 404:
            raise FetchError(f"Extension not found: {extension_id}")
        if resp.status_code != 200:
            raise FetchError(f"Edge Add-ons returned {resp.status_code}")
        return _parse_page(resp.text, extension_id, url)

    async def download_package(self, extension_id: str) -> bytes:
        url = _DOWNLOAD_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code != 200:
            raise FetchError(f"CRX download returned {resp.status_code}")
        return _strip_crx_header(resp.content)


def _parse_page(html: str, extension_id: str, url: str) -> ExtensionMetadata:
    """Parse the Edge Add-ons page.

    The store is a React SPA — server-rendered HTML only contains the page
    title and a user-count meta tag. Publisher, version, and last-updated are
    filled in later from the downloaded CRX manifest by _fetch_and_score.
    """
    soup = BeautifulSoup(html, "html.parser")

    name = _extract_name(soup, extension_id)

    description: str | None = None
    desc_meta = soup.find("meta", {"name": "description"})
    if desc_meta:
        description = desc_meta.get("content") or None

    install_count: int | None = None
    # The only server-rendered count data lives in this meta tag
    count_meta = soup.find("meta", attrs={"itemprop": "userInteractionCount"})
    if count_meta is None:
        count_meta = soup.find("meta", attrs={"itemProp": "userInteractionCount"})
    if count_meta:
        try:
            install_count = int(str(count_meta.get("content", "")).replace(",", "").strip())
        except ValueError:
            pass

    return ExtensionMetadata(
        name=name,
        publisher="",
        description=description,
        version="",
        install_count=install_count,
        last_updated=None,
        store_url=url,
    )


def _extract_name(soup: BeautifulSoup, fallback: str) -> str:
    title_tag = soup.find("title")
    if title_tag:
        raw = title_tag.get_text(strip=True)
        for suffix in _TITLE_SUFFIXES:
            if raw.endswith(suffix):
                return raw[: -len(suffix)].strip()
        if raw:
            return raw
    return fallback
