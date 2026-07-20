import re
from datetime import datetime

from bs4 import BeautifulSoup

from app.fetchers.base import BaseFetcher, ExtensionMetadata, FetchError

_DATE_FORMATS = ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d")

# hl=en pins the page to English (#279): the label-adjacency extraction below and
# _parse_date's English month names both break on a localized page, which Google
# serves by egress IP — a non-US deployment otherwise gets "Aktualisiert"/"17. Juli
# 2025", last_updated stays None forever, and staleness silently scores 10
# ("unknown") for a freshly-updated extension. The Edge fetcher already pins hl.
_DETAIL_URL = "https://chromewebstore.google.com/detail/{extension_id}?hl=en"
_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=130.0&acceptformat=crx3"
    "&x=id%3D{extension_id}%26uc"
)


class ChromeFetcher(BaseFetcher):
    async def fetch_metadata(self, extension_id: str) -> ExtensionMetadata:
        url = _DETAIL_URL.format(extension_id=extension_id)
        # Belt-and-braces with hl=en: some Google endpoints weigh the header when
        # the query param is absent/ignored (#279).
        resp = await self.client.get(url, follow_redirects=True, headers={"Accept-Language": "en-US,en"})
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

    last_updated = _parse_date(_find_detail_value(soup, "updated"))

    # Version via label adjacency in the Details section, like `updated`/`offered by`
    # (#279). The whole-page regex below is fallback only: the description renders as
    # visible body text BEFORE the details section, so "New in Version 9.9.9" there
    # used to hijack the regex on every fetch — one spurious new_version alert, then a
    # permanently wrong stored version. `exact=True` keeps the label lookup itself from
    # matching description prose that merely contains the word.
    version = _find_detail_value(soup, "version", exact=True)
    if not re.fullmatch(r"[0-9][0-9.]*", version):
        version = ""

    # The version and user-count regexes take the FIRST match, so they must
    # only see *visible* page text: the raw document's <head> meta description
    # (an attribute, invisible to get_text) and body <script> JSON blobs both
    # re-embed the description, where e.g. "Join 1,000,000 users" would hijack
    # the real count (#142). Decompose scripts/styles last — the soup-based
    # extractions above are done with it.
    for tag in soup.find_all(["script", "style"]):
        tag.decompose()
    visible = soup.get_text(" ")

    if not version:
        # Fallback for pages carrying only the inline "Version: x.y.z" form (no
        # label/value split for exact-label lookup). Require the COLON separator
        # (#279 review): a whitespace-tolerant `Version[:\s]+` still let earlier
        # description prose like "New in Version 9.9.9" win over the real
        # "Version: 1.54.0", reproducing the very hijack this fix targets.
        version_m = re.search(r"Version\s*:\s*([0-9][0-9.]*)", visible)
        if version_m:
            version = version_m.group(1)

    install_count = None
    count_m = re.search(r"([\d,]+)\s+users?", visible, re.IGNORECASE)
    if count_m:
        try:
            install_count = int(count_m.group(1).replace(",", ""))
        except ValueError:
            pass

    return ExtensionMetadata(
        name=name,
        publisher=publisher,
        description=description,
        version=version,
        install_count=install_count,
        last_updated=last_updated,
        store_url=url,
    )


def _find_detail_value(soup: BeautifulSoup, label: str, *, exact: bool = False) -> str:
    """Find a value in the details section by its label text (e.g. 'Offered by', 'Updated').

    ``exact=True`` requires the text node to BE the label (ignoring whitespace), not
    merely contain it — needed for labels like 'Version' that also occur in
    description prose (#279).
    """
    if exact:
        pattern = re.compile(rf"^\s*{re.escape(label)}\s*$", re.IGNORECASE)
    else:
        pattern = re.compile(re.escape(label), re.IGNORECASE)
    for elem in soup.find_all(string=pattern):
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
