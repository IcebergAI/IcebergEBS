---
title: Risk scoring
icon: material/gauge
---

<p class="eyebrow">How it works</p>

# Risk scoring

Every tracked extension carries a **0–100 risk score**. It is the sum of six
independent signals, each capped at its own maximum, with the total capped at 100.

| Signal | Max | What it measures |
|---|---:|---|
| **Permissions** | 25 | The most dangerous capability the manifest asks for |
| **Popularity** | 20 | Small install base, or a sudden collapse in installs |
| **Publisher** | 15 | Identity changes, unverified publishers, generic names |
| **Staleness** | 15 | How long since the extension was last updated |
| **Code behaviour** | 15 | `eval`, remote code loading, obfuscation, minification |
| **External domains** | 10 | How many distinct domains the code reaches out to |

Higher is worse. The score is recomputed on **every** fetch — scheduled or manual —
and stored alongside a per-signal breakdown you can expand on the extension detail
page.

!!! warning "Unknown is not zero"
    Four of the six signals return a **midpoint** rather than 0 when the underlying
    data is missing, because "we could not look" is not the same as "we looked and
    it was fine":

    | Situation | Contribution |
    |---|---:|
    | Install count unavailable | 10 |
    | Last-updated date unavailable | 10 |
    | Package could not be downloaded or read | 7 (code behaviour) |
    | Package could not be downloaded or read | 5 (external domains) |

    An extension whose package fails to download therefore starts at **12** before
    anything is actually known about it, and can reach 22 if the store metadata is
    thin too. This is deliberate: an unanalysable extension should not look clean.

## The six signals

### Permissions — up to 25

Scored against the **union** of `permissions` and `host_permissions`, so Manifest V2
and V3 spellings both count. It is a tier, not a sum — the worst permission present
sets the score:

| Score | Tier | Examples |
|---:|---|---|
| **25** | Critical | `<all_urls>`, `debugger`, `nativeMessaging`, `proxy`, `webRequest`, `webRequestBlocking`, `declarativeNetRequestWithHostAccess`, `desktopCapture` — or a broad host pattern (`*://*/*`, `http://*/*`, `https://*/*`) |
| **15** | High | `cookies`, `history`, `tabs`, `browsingData`, `downloads`, `management`, `clipboardRead`, `contentSettings`, `pageCapture`, `tabCapture`, `audioCapture`, `videoCapture`, `webNavigation` |
| **7** | Medium | `storage`, `notifications`, `contextMenus`, `bookmarks`, `identity`, `geolocation`, `scripting`, `privacy`, `sessions`, `topSites`, `declarativeNetRequest`, `clipboardWrite` |
| **0** | — | Nothing above |

The **capture/surveillance family** is scored deliberately: arbitrary desktop
screen capture (`desktopCapture`) is critical — it reaches every window and app,
not just the browser — while live tab audio/video capture and the full
browsing-graph telemetry of `webNavigation` are high.

The tier lists live in `app/permissions.py` and are shared with the package
inspector, so a permission is classified identically wherever it is read.

### Popularity — up to 20

| Install count | Base |
|---|---:|
| Unknown | 10 |
| < 100 | 16 |
| < 1,000 | 8 |
| < 10,000 | 4 |
| ≥ 10,000 | 0 |

A **sudden drop** adds 10 (capped at 20): if the install count has fallen by more
than **30%** since the previous reading. This compares the last stored reading with
the current one — it is a step change detector, not a long-run trend.

### Publisher — up to 15

Additive:

- **+8** — the publisher name changed since the previous fetch
- **+4** — the publisher is explicitly **not** domain-verified
- **+3** — the publisher name looks generic (e.g. "Extension Tools Ltd" — corporate
  suffixes are stripped, and every remaining word must be a filler word like
  *extension*, *tool*, *addon*, *plugin*)

!!! note "Verification is VS Code only"
    Only the VS Code Marketplace exposes a publisher-verification flag. For Chrome
    and Edge the state is *unknown*, not *unverified*, so the +4 never applies —
    absence of the flag is never treated as a negative signal.

### Staleness — up to 15

| Last updated | Score |
|---|---:|
| Unknown | 10 |
| > 3 years ago | 15 |
| > 2 years ago | 11 |
| > 1 year ago | 7 |
| > 180 days ago | 4 |
| Within 180 days | 0 |

### Code behaviour — up to 15

**No package analysis → a flat 7.** Otherwise additive:

- **+8** — uses `eval` or `new Function`
- **+5** — loads remote code (`fetch("http…")`, `importScripts`, `new WebSocket`,
  an injected `<script>` element, a remote `<script src>` in a bundled HTML page…)
- **+5** at the top obfuscation score, **+3** at a moderate one
- **+ up to 7** from individual code findings, weighted `critical 6 / high 4 /
  medium 2`

Only findings that come from **executable code** feed this signal — manifest-derived
findings such as *broad host access* or *high-risk permission* are surfaced in the
findings list but do not double-count here, because the permissions signal already
scored them.

### External domains — up to 10

Counted as **distinct registrable domains** (eTLD+1, via the Public Suffix List) —
so a dozen subdomains of one CDN count once. Well-known platform and CDN domains
(Google APIs, jsDelivr, cdnjs, unpkg, Visual Studio assets, …) are excluded.

| Distinct domains | Score |
|---|---:|
| Unknown (no analysis) | 5 |
| 0 | 0 |
| 1–2 | 3 |
| 3–5 | 6 |
| More than 5 | 10 |

Full hostnames are still recorded for display and for manual threat-intel lookups —
only the *score* collapses them to registrable domains.

## Risk bands

| Band | Score |
|---|---|
| <span class="risk-chip low">Low</span> | 0 – 24 |
| <span class="risk-chip medium">Medium</span> | 25 – 49 |
| <span class="risk-chip high">High</span> | 50 – 74 |
| <span class="risk-chip critical">Critical</span> | 75 – 100 |

Bands are what alerting fires on: crossing a band boundary raises a
`risk_level_change` event, while score drift *within* a band does not. Thresholds are
defined once, in `app/scoring.py`.

## Package inspection

IcebergEBS does not score store metadata alone — it downloads the actual package
(Chrome/Edge **CRX**, VS Code **VSIX**) and reads the code inside it.

**What it inspects.** The manifest, plus every script file: not just `*.js`, but
`.mjs`, `.cjs`, `.jsx`, `.html`, and — regardless of file name — every path the
manifest declares executable (background service worker, content scripts, popups,
options pages, devtools pages, sandboxed pages, the VS Code `main`/`browser` entry
point). Bundled HTML is parsed with a real HTML parser, and only genuinely
executable `<script>` bodies are scanned; a remote `<script src>` is a **critical**
finding on its own.

**What it looks for.** `eval` / `new Function` / string-argument timers; remote code
loading; script-element injection; minification (very long lines in a very short
file); obfuscation (single- and two-character identifier density, escape-sequence
density); and every `http(s)://` literal in the source.

**Limits.** Downloads are capped at **64 MiB** on the wire. An archive is rejected if
it declares more than **500 entries** or more than **50 MB** uncompressed; individual
files over **5 MB** are skipped; findings are capped at 200. A path containing `..`
is never resolved out of the archive.

!!! danger "What inspection is not"
    - **No code is executed.** Inspection is archive reads plus pattern matching —
      it runs entirely on CPU, in a worker thread, and never evaluates extension
      code.
    - **No AST or semantic analysis**, so it is defeatable by construction —
      `window['ev'+'al']` will not match. This is a *risk signal*, not a safety
      proof, which is exactly why an unanalysable package scores the midpoint
      rather than zero.
    - **Nothing is submitted to a third party.** No package or hash is uploaded to
      an external scanning service; the threat-intel links on the detail page are
      manual lookups you choose to follow.

    A parseable manifest is required: a manifest that is present but **unreadable**
    fails the inspection rather than returning an empty result, so a corrupt archive
    can never silently erase an extension's stored permissions.

## Per-store coverage

The three stores expose different data, so not every signal is available everywhere.

| | Chrome Web Store | Edge Add-ons | VS Code Marketplace |
|---|---|---|---|
| **Source** | HTML scraping | Undocumented JSON API | Official gallery REST API |
| **Package** | CRX | CRX, falling back to a manifest-only archive | VSIX |
| **Install count** | Scraped | `activeInstallCount` | `install` statistic |
| **Permissions signal** | ✅ | ✅ | ➖ no Chrome permission model |
| **Publisher verified** | ➖ unknown | ➖ unknown | ✅ domain verification |

Two consequences worth knowing:

- **Chrome data is scraped**, so a store layout change can make fields disappear.
  When that happens IcebergEBS keeps the previously stored value rather than scoring
  the gap as a change — a scraper regression must never masquerade as an alert.
- **Edge falls back** to an archive containing only the manifest when the CRX
  download fails. Permissions still score correctly, but code behaviour and external
  domains are then measured against an empty code corpus, so an Edge extension can
  score *lower* than an equivalent Chrome one whose package simply failed to
  download. Check the detail page for whether a package was analysed before
  comparing across stores.

## Refresh and re-scoring

A background scheduler refreshes every **watchlisted** extension on an interval —
**60 minutes** by default (`ICEBERG_EBS_FETCH_INTERVAL_MINUTES`). Each extension is
fetched, inspected, re-scored, and committed independently, so one failure cannot
roll back the rest of the cycle. A per-store **circuit breaker** stops hammering a
store that is down: after a threshold of consecutive failures the remaining
extensions for that store are skipped and the outage is recorded.

Every fetch writes a log entry carrying the score before and after, which is what the
history charts and the change alerts are built from. The **first** fetch of a newly
added extension never raises alerts — there is no prior state to compare against.

[:octicons-arrow-right-24: What gets alerted on, and the API](alerts.md)
