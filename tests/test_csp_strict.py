"""The strict-CSP invariants (#106): no inline scripts, `script-src 'self'`.

This replaces tests/test_csp_hash.py and inverts its contract. That test verified
that the CSP's sha256 pin matched the one allowed inline script (the anti-flash
theme bootstrap); #106 removed the inline script entirely — the bootstrap is the
external static/js/theme-boot.js, Alpine is the @alpinejs/csp build, and every
component is registered from same-origin files. The new guard is strictly
stronger: it covers EVERY template, not one script, and pins the policy itself.

Nothing at runtime notices a regression on pages the e2e suite doesn't visit: the
browser silently refuses to run a reintroduced inline script and that page's
behaviour quietly breaks in production. This test makes it a CI failure instead.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = sorted((_ROOT / "app" / "templates").glob("*.html"))
_CSP_FILES = [
    _ROOT / "caddy/headers.caddy",
    # The Helm K8s ConfigMap embeds a mirror of caddy/headers.caddy (Helm can't read
    # files above the chart); check it too so the two copies can't silently drift.
    _ROOT / "helm/iceberg-ebs/templates/caddy-configmap.yaml",
]

# Any <script> tag: must either load a same-origin file (src=) or be a data island
# (type="application/json", inert — never executed).
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.IGNORECASE)


def _csp_values(csp_file: Path) -> list[str]:
    values = re.findall(r"Content-Security-Policy \"([^\"]+)\"", csp_file.read_text(encoding="utf-8"))
    assert values, f"no Content-Security-Policy header found in {csp_file}"
    return values


def test_no_inline_scripts_in_any_template():
    offenders: list[str] = []
    for template in _TEMPLATES:
        for lineno, line in enumerate(template.read_text(encoding="utf-8").splitlines(), 1):
            for tag in _SCRIPT_TAG.findall(line):
                if "src=" in tag or 'type="application/json"' in tag:
                    continue
                offenders.append(f"{template.name}:{lineno}: {tag}")
    assert not offenders, (
        "Inline <script> blocks are forbidden under script-src 'self' (#106) — move "
        "the code to a file under static/js/ (Alpine components go in the "
        'Alpine.data registry; server data goes in a type="application/json" '
        "island):\n" + "\n".join(offenders)
    )


def test_no_inline_event_handlers_in_any_template():
    """onclick=/onload=/… attributes are inline-script surface the CSP blocks."""
    handler = re.compile(r"<[^>]*\son[a-z]+\s*=", re.IGNORECASE)
    offenders = [
        f"{t.name}:{n}: {line.strip()}"
        for t in _TEMPLATES
        for n, line in enumerate(t.read_text(encoding="utf-8").splitlines(), 1)
        if handler.search(line)
    ]
    assert not offenders, (
        "Inline on*= handlers are forbidden under script-src 'self' (#106) — use an "
        "Alpine @event binding backed by a registered component method:\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("csp_file", _CSP_FILES, ids=lambda p: p.name)
def test_script_src_is_exactly_self(csp_file: Path):
    for value in _csp_values(csp_file):
        directives = dict(
            (stripped.split(None, 1) + [""])[:2] for part in value.split(";") if (stripped := part.strip())
        )
        assert directives.get("script-src") == "'self'", (
            f"{csp_file}: script-src must be exactly \"'self'\" (#106) — no hashes, "
            f"no hosts, no unsafe-*; got: {directives.get('script-src')!r}"
        )


@pytest.mark.parametrize("csp_file", _CSP_FILES, ids=lambda p: p.name)
def test_no_hash_pins_remain(csp_file: Path):
    """The old sha256 pin must not linger anywhere in the CSP files — a leftover pin
    means an inline script somewhere is expected to execute."""
    assert "sha256-" not in csp_file.read_text(encoding="utf-8"), (
        f"{csp_file}: a sha256- source survived the strict-CSP migration (#106); "
        "there are no allowed inline scripts anymore"
    )
