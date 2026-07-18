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


# A raw neutral keyword (white/black) or hex neutral as a *colour* value hard-codes
# a colour that doesn't flip with the theme — #229 was `color:white` on the active
# filter pill, which rendered white-on-near-white in dark mode. The house rule is
# "never hard-code a neutral colour; use the --paper/--ink/... tokens". Anchored on
# colour-type properties so it can't trip on `white-space`.
_RAW_NEUTRAL_COLOUR = re.compile(
    r"(?:color|background|background-color|border-color)\s*:\s*"
    r"(?:white|black|#(?:fff|000|ffffff|000000))\b",
    re.IGNORECASE,
)


def test_no_raw_neutral_colour_in_templates() -> None:
    """Inline styles must use the house neutral tokens (var(--paper)/var(--ink)/…),
    never a raw white/black keyword or #fff/#000 — those don't flip with the theme
    and produce unreadable contrast in one mode (#229)."""
    offenders = [
        f"{path.relative_to(REPO)}:{lineno}: {line.strip()[:120]}"
        for path in sorted(TEMPLATE_DIR.glob("*.html"))
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _RAW_NEUTRAL_COLOUR.search(line)
    ]
    assert not offenders, (
        "Hard-coded neutral colours don't flip with html[data-theme] and break "
        "contrast in one mode (#229). Use var(--paper)/var(--ink)/var(--surface) "
        "from iceberg.css:\n" + "\n".join(offenders)
    )
