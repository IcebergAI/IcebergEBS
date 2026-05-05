import re
from datetime import datetime

import httpx
from bs4 import BeautifulSoup

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

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


_DATE_FORMATS = (
    "%B %d, %Y",   # January 10, 2024
    "%b %d, %Y",   # Jan 10, 2024
    "%m/%d/%Y",    # 01/10/2024  (Edge uses this)
    "%Y-%m-%d",    # 2024-01-10
)


def _parse_page(html: str, extension_id: str, url: str) -> ExtensionMetadata:
    soup = BeautifulSoup(html, "html.parser")

    name = _extract_name(soup, extension_id)

    # Publisher: Edge uses "Offered by" or "Developer" in the details list
    publisher = _find_dt_value(soup, "offered by") or _find_dt_value(soup, "developer")

    description = None
    desc_meta = soup.find("meta", {"name": "description"})
    if desc_meta:
        description = desc_meta.get("content")

    version = _find_dt_value(soup, "version") or ""

    install_count = None
    raw_users = _find_dt_value(soup, "users")
    if raw_users:
        try:
            install_count = int(raw_users.replace(",", "").replace("+", "").strip())
        except ValueError:
            pass

    # Edge labels this "Last updated" or just "Updated"
    raw_date = _find_dt_value(soup, "last updated") or _find_dt_value(soup, "updated")
    last_updated = _parse_date(raw_date)

    return ExtensionMetadata(
        name=name,
        publisher=publisher or "",
        description=description,
        version=version,
        install_count=install_count,
        last_updated=last_updated,
        store_url=url,
    )


def _extract_name(soup: BeautifulSoup, fallback: str) -> str:
    # og:title is the most reliable — Edge sets it to the bare extension name
    og = soup.find("meta", {"property": "og:title"})
    if og and og.get("content", "").strip():
        return og["content"].strip()

    # <title> tag has format "Name - Microsoft Edge Addons"
    title_tag = soup.find("title")
    if title_tag:
        raw = title_tag.get_text(strip=True)
        # Strip common suffixes
        for suffix in (" - Microsoft Edge Addons", " – Microsoft Edge Addons", " | Microsoft Edge Addons"):
            if raw.endswith(suffix):
                return raw[: -len(suffix)].strip()

    # Last resort: first <h1> on the page
    h1 = soup.find("h1")
    if h1:
        text = h1.get_text(strip=True)
        if text:
            return text

    return fallback


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _find_dt_value(soup: BeautifulSoup, label: str) -> str | None:
    """Find the <dd> text following a <dt> whose text matches label (case-insensitive)."""
    for dt in soup.find_all("dt"):
        if label.lower() in dt.get_text(strip=True).lower():
            dd = dt.find_next_sibling("dd")
            if dd:
                return dd.get_text(strip=True)
    return None
