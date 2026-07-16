"""#85: the frontend is fully self-hosted — no third-party origin at runtime.

Two layers, guarding both halves of the contract:

1. No template may LOAD an asset (script/style/font/image/frame) from an external
   origin. Navigation links (``<a href>``) and dynamic hrefs built by the app
   (e.g. the manual VirusTotal/OTX lookup links) are deliberately out of scope —
   the gate is about what executes/renders in the page, not where a user may go.
2. The canonical CSP (caddy/headers.caddy and its test-guarded Helm mirror) must
   not allowlist any scheme://host source. A reintroduced CDN tag would otherwise
   only fail at runtime (blocked by the same-origin CSP) — or worse, merge cleanly
   if the CSP were quietly widened to match.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO / "app" / "templates"
CSP_FILES = (
    REPO / "caddy" / "headers.caddy",
    REPO / "helm" / "iceberg-ebs" / "templates" / "caddy-configmap.yaml",
)

# Asset-loading tags with a literal absolute URL. <script src>, <link href>
# (stylesheets/fonts/icons), <img>/<source>/<iframe>/<embed> src.
_EXTERNAL_ASSET = re.compile(
    r"<(?:script|link|img|source|iframe|embed)\b[^>]*?"
    r"(?:src|href)\s*=\s*[\"'](?://|https?://)",
    re.IGNORECASE,
)
# preconnect/dns-prefetch/preload hints re-introduce a third-party dependency even
# without a direct asset tag.
_EXTERNAL_HINT = re.compile(
    r"<link\b[^>]*?rel\s*=\s*[\"'](?:preconnect|dns-prefetch|preload)[\"'][^>]*?"
    r"href\s*=\s*[\"'](?://|https?://)",
    re.IGNORECASE,
)


def test_templates_load_no_external_assets() -> None:
    offenders: list[str] = []
    for path in sorted(TEMPLATE_DIR.glob("*.html")):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if _EXTERNAL_ASSET.search(line) or _EXTERNAL_HINT.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Templates must not load assets from third-party origins (#85) — "
        "vendor the asset under static/ instead:\n" + "\n".join(offenders)
    )


def test_csp_allowlists_no_external_origin() -> None:
    for path in CSP_FILES:
        csp_lines = [line for line in path.read_text().splitlines() if "Content-Security-Policy" in line]
        assert csp_lines, f"no CSP header found in {path}"
        for line in csp_lines:
            assert "://" not in line.split(None, 1)[1], (
                f"{path}: the CSP must not allowlist an external origin (#85); "
                "every source directive is same-origin only"
            )
