---
description: Store-specific fetcher + package-inspection notes (Chrome/VS Code/Edge, CRX/VSIX)
paths:
  - "app/fetchers/**"
  - "app/inspector.py"
---

# Store-specific fetcher notes

## Chrome Web Store (`app/fetchers/chrome.py`)
- Scrapes `https://chromewebstore.google.com/detail/{extension_id}` with BeautifulSoup4
- Publisher extracted via `_find_detail_value(soup, "offered by")` — finds text node then reads next sibling element
- Last updated extracted via `_find_detail_value(soup, "updated")` then `_parse_date()`
- Downloads CRX from `clients2.google.com/service/update2/crx`
- CRX3 format: a binary header precedes the zip payload. The fetchers download the raw CRX as-is; the header is stripped downstream by `inspector._zip_payload()`, which seeks the `PK\x03\x04` zip magic before reading the archive (the fetchers do **not** pre-strip it)

## VS Code Marketplace (`app/fetchers/vscode.py`)
- Uses the public gallery REST API: `POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery` with flags `914`
- Extension ID format: `publisher.extensionName`
- `fetch()` is overridden to make a single API call for both metadata and the VSIX download URL (the base class would otherwise call the API twice)
- Downloads `.vsix` (plain zip, no header stripping needed)

## Edge Add-ons (`app/fetchers/edge.py`)
- The store frontend is a React SPA — static HTML has almost no useful data
- Uses the undocumented product details API discovered via browser XHR inspection:
  `GET https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}?hl=en-US`
- Response fields used: `name`, `developer` (publisher), `version`, `activeInstallCount`, `lastUpdateDate` (Unix timestamp), `description`
- The response also includes the full `manifest` JSON string (with `permissions`, `host_permissions`) and `averageRating`/`ratingCount` (not currently used)
- `fetch()` is overridden to use a two-stage package strategy:
  1. **Guaranteed baseline**: the `manifest` string from the API response is wrapped in a minimal in-memory zip and passed to the inspector — permissions are always available
  2. **Upgrade attempt**: the CRX download is tried (`edge.microsoft.com/extensionwebstorebase/v1/crx`) for full JS static analysis; if it succeeds, the full package replaces the baseline
- CRX download URL format: `?x=id%3D{id}%26installsource%3Dondemand&response=redirect` — the `installsource=ondemand` parameter (URL-encoded within the `x` value) is required; other formats (`%26uc`, `installsource=webstore`) return HTTP 500

## Package inspection (`app/inspector.py`)
- Handles both CRX (header already stripped by fetcher) and VSIX (plain zip)
- Extracts: permissions, host_permissions, eval usage, remote fetch calls, obfuscation score, external domains, minification
- **What gets scanned is not just `*.js`** (#275). `_script_files()` returns the union of (a) entries with a `.js`/`.mjs`/`.cjs`/`.jsx`/`.html`/`.htm` suffix and (b) every path `_manifest_referenced_paths()` finds declared as executable in the manifest — background service worker/scripts/page, `content_scripts[].js`, popup/options/devtools/sandbox pages, VS Code `main`/`browser` — **regardless of extension**, because Chrome loads whatever the manifest names. Manifest paths are resolved against the archive tolerating a leading `/`/`./` and the VSIX `extension/` root; a `..` segment is dropped, never resolved. Suffix-only selection made the entire code-behaviour and network scoring evadable by renaming a payload to `bg.mjs`, which scored *below* an undownloadable package
- HTML entries go through `_analyse_html()`, which **masks** everything outside `<script>` bodies (blanking to spaces, newlines preserved) before running the JS scan — so reported line numbers stay true to the HTML file and markup can't trip the minification/obfuscation heuristics. A remote `<script src>` is flagged separately as `remote_script_include` and its host recorded as an external domain
- Extracts `author` and `version` from the manifest; only `author` is used as a publisher fallback in `services.py`, and only when neither the store page nor a previously stored value provides one — it must never override a stored publisher, or an author/publisher mismatch would flap `publisher_change` alerts on every partial parse (#142); `version` from the manifest is intentionally not used — updating `ext.version` only from store metadata avoids spurious `new_version` alerts when Chrome HTML scraping is unreliable
- `_SAFE_DOMAINS` filters out well-known CDNs from the external domain list
