---
description: Store-specific fetcher + package-inspection notes (Chrome/VS Code/Edge, CRX/VSIX)
paths:
  - "app/fetchers/**"
  - "app/inspector.py"
---

# Store-specific fetcher notes

## Chrome Web Store (`app/fetchers/chrome.py`)
- Scrapes `https://chromewebstore.google.com/detail/{extension_id}?hl=en` with BeautifulSoup4 — the `hl=en` pin + `Accept-Language: en-US,en` header are load-bearing (#279): Google localizes by egress IP, and the label lookups + English-month `_parse_date` silently break on a localized page (staleness then scores 10 "unknown" forever)
- Publisher extracted via `_find_detail_value(soup, "offered by")` — finds text node then reads next sibling element
- Last updated extracted via `_find_detail_value(soup, "updated")` then `_parse_date()`
- Version extracted via `_find_detail_value(soup, "version", exact=True)` (exact label match, so description prose containing "Version" can't hijack it, #279), validated against `[0-9][0-9.]*`. Real Chrome uses the **inline** `<div>Version: 1.54.0</div>` form (label+value in one node) for Version even though Updated/Offered by use the split label/value form, so exact-label returns empty and an inline path runs — but it is **anchored to the Details region** (`anchor.find_all_next` from the "Updated"/"Offered by" label, each candidate `re.fullmatch`-ed to be essentially just `Version: x.y.z`). The description/What's-new section renders BEFORE those labels, so even a standalone `Version: 9.9.9` prose node there is out of scope. No Details anchor (a partial page) → version stays empty (keep-stale). Never reintroduce a whole-visible-page `re.search`/`stripped_strings` scan here — a document-order scan is hijackable by an earlier description node (#279)
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
- HTML entries go through `_analyse_html()`, which finds script boundaries with **BeautifulSoup, not a regex** — `</script foo>`, `</script\n>`, a `</script>` inside a string literal, and a `<script>` inside an HTML comment all have surprising-but-definite parser answers, and a regex that gets one wrong either masks a payload out of the scan or invents findings for code the browser never runs (CodeQL flagged exactly this as `py/bad-tag-filter`). The page is then **masked** down to the parsed script bodies — everything else replaced by its newlines alone — so reported line numbers stay true to the file and markup can't trip the minification/obfuscation heuristics (blanking to *spaces* does not work: a long line of minified markup still measures as a long line). A remote `<script src>` is read off the parsed tag, flagged `remote_script_include` (critical), and its host recorded as an external domain. Cost is ~0.5s/MB, the same as the existing JS regex scan, so the `_MAX_TOTAL_BYTES` envelope is unchanged
- **The JS layer is regex-based and deliberately heuristic.** It is a risk *signal*, not a safety proof: `eval` reached via `window['ev'+'al']` defeats it, as it would defeat naive AST matching. That is why obfuscation is itself a scored signal and why an unanalysable package scores at the unknown-midpoint rather than zero — the model must never reward being unreadable
- **A manifest that is present but unreadable raises `InspectorError`** rather than returning an analysis (#274). This is the non-obvious invariant: an analysis with `permissions == []` is still **truthy**, so `services._effective_values` prefers it over the stored values and `_apply_fetch_results` writes `permissions = "[]"` — zeroing a real extension's permissions and firing a spurious `permission_change` "removal" alert. The #142 keep-stale guard only covers `analysis is None`. Raising routes an unreadable manifest through that same path; scoring then falls back to the unknown-midpoint, which is deliberately *higher* than a falsely clean zero. This covers unparsable JSON, valid-JSON-wrong-shape (a bare list), **and** an over-limit manifest — the last of which used to be silently skipped
- `_read_manifest_json` decodes with **`utf-8-sig`** and, on a parse failure, retries after `_strip_json_comments` — Chrome itself tolerates a BOM and `//` / `/* */` comments in `manifest.json`, so such packages are live in the stores. The comment stripper is **string-aware**: a naive strip cuts `"homepage_url": "https://…"` at the `//` and manufactures the parse error it exists to prevent
- **VS Code packages are classified by the file the manifest came from**, not by its body (`_is_vscode_package`): `_load_manifest` only falls through to `package.json` when there is no `manifest.json`, so the filename is the strongest signal — and it used to be computed and discarded. The old `"contributes" in manifest` test missed extension packs (`extensionPack`) and API-only extensions (`main` + `activationEvents`), which fell through to the Chrome path and got `manifest.get("manifest_version", 2)` → a bogus MV2 finding (+2 code-behaviour) rendering a Chrome-specific claim on a VSIX. `engines.vscode` is kept as a second signal for a VSIX that also ships a `manifest.json`
- Extracts `author` and `version` from the manifest; only `author` is used as a publisher fallback in `services.py`, and only when neither the store page nor a previously stored value provides one — it must never override a stored publisher, or an author/publisher mismatch would flap `publisher_change` alerts on every partial parse (#142); `version` from the manifest is intentionally not used — updating `ext.version` only from store metadata avoids spurious `new_version` alerts when Chrome HTML scraping is unreliable
- `_SAFE_DOMAINS` filters out well-known CDNs from the external domain list
