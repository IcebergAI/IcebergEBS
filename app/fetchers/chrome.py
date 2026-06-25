import re
from datetime import datetime

from bs4 import BeautifulSoup

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

_DATE_FORMATS = ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d")

_DETAIL_URL = "https://chromewebstore.google.com/detail/{extension_id}"
_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=130.0&acceptformat=crx3"
    "&x=id%3D{extension_id}%26uc"
)


class ChromeFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        url = _DETAIL_URL.format(extension_id=extension_id)
        resp = await self.client.get(url, follow_redirects=True)
        if resp.status_code == 404:
            raise FetchError(f"Extension not found: {extension_id}")
        if resp.status_code != 200:
            raise FetchError(f"Chrome Web Store returned {resp.status_code}")

        metadata = _parse_page(resp.text, extension_id, url)
        return metadata

    async def download_package(self, extension_id: str) -> bytes:
        url = _DOWNLOAD_URL.format(extension_id=extension_id)
        return await self._get_package_bytes(url)


def _parse_page(html: str, extension_id: str, url: str) -> ExtensionMetadata:
    soup = BeautifulSoup(html, "html.parser")

    name_tag = soup.find("h1")
    name = name_tag.get_text(strip=True) if name_tag else extension_id

    pub_tag = soup.find("a", attrs={"data-publisher-id": True})
    if pub_tag:
        publisher = pub_tag.get_text(strip=True)
    else:
        sapd = soup.find("div", class_="mdSapd")
        publisher = next(sapd.strings, "").strip() if sapd else _find_detail_value(soup, "offered by")

    description = None
    desc_tag = soup.find("meta", {"name": "description"})
    if desc_tag:
        description = desc_tag.get("content")

    version = ""
    version_m = re.search(r"Version[:\s]+([0-9][0-9.]*)", html)
    if version_m:
        version = version_m.group(1)

    install_count = None
    count_m = re.search(r"([\d,]+)\s+users?", html, re.IGNORECASE)
    if count_m:
        try:
            install_count = int(count_m.group(1).replace(",", ""))
        except ValueError:
            pass

    last_updated = _parse_date(_find_detail_value(soup, "updated"))

    return ExtensionMetadata(
        name=name,
        publisher=publisher,
        description=description,
        version=version,
        install_count=install_count,
        last_updated=last_updated,
        store_url=url,
    )


def _find_detail_value(soup: BeautifulSoup, label: str) -> str:
    """Find a value in the details section by its label text (e.g. 'Offered by', 'Updated')."""
    for elem in soup.find_all(string=re.compile(re.escape(label), re.IGNORECASE)):
        parent = elem.parent
        sibling = parent.find_next_sibling()
        if sibling:
            text = sibling.get_text(strip=True)
            if text:
                return text
        if parent.parent:
            next_item = parent.parent.find_next_sibling()
            if next_item:
                text = next_item.get_text(strip=True)
                if text:
                    return text
    return ""


def _parse_date(raw: str) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None
