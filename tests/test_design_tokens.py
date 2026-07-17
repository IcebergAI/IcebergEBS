"""The house design system's token discipline (#105/#212).

The pre-house `--ink-0..8` scale (and `--accent-bg`) was swept out of the
templates and its app.css alias bridge removed. A reintroduced legacy token
would silently render as *nothing* (an undefined custom property drops the
whole declaration), so guard the sweep in CI. Severity colours are equally
locked down: the only sanctioned non-neutral literals live in app.css's
--risk-* block, so no template or first-party JS may carry an oklch literal.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO / "app" / "templates"
JS_DIR = REPO / "static" / "js"

_LEGACY_TOKEN = re.compile(r"var\(--(?:ink-[0-8]|accent-bg)\)")


def _first_party_js() -> list[Path]:
    return [p for p in sorted(JS_DIR.rglob("*.js")) if "vendor" not in p.parts]


def test_no_legacy_tokens_in_templates_or_js() -> None:
    offenders = [
        f"{path.relative_to(REPO)}:{lineno}: {line.strip()[:120]}"
        for path in [*sorted(TEMPLATE_DIR.glob("*.html")), *_first_party_js()]
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _LEGACY_TOKEN.search(line)
    ]
    assert not offenders, (
        "The legacy --ink-N/--accent-bg tokens were removed in #212 — an undefined "
        "custom property silently drops the declaration. Use the house tokens from "
        "static/css/iceberg.css instead:\n" + "\n".join(offenders)
    )


def test_no_oklch_literals_outside_the_stylesheets() -> None:
    """Severity/neutral colours live in the CSS token blocks only; the one
    sanctioned exception is the pre-paint --paper background pair in
    theme-boot.js/app.js (kept in sync with iceberg.css by hand)."""
    allowed = {"theme-boot.js", "app.js"}
    offenders = [
        f"{path.relative_to(REPO)}:{lineno}: {line.strip()[:120]}"
        for path in [*sorted(TEMPLATE_DIR.glob("*.html")), *_first_party_js()]
        if path.name not in allowed
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"oklch\(\s*[\d.]", line)
    ]
    assert not offenders, (
        "oklch colour literals belong in the CSS token blocks (iceberg.css / "
        "app.css --risk-*), not in templates or JS (#105):\n" + "\n".join(offenders)
    )
