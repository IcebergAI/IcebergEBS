"""The strict-CSP invariants (#106): no inline scripts, `script-src 'self'`.

This replaces tests/test_csp_hash.py and inverts its contract. That test verified
that the CSP's sha256 pin matched the one allowed inline script (the anti-flash
theme bootstrap); #106 removed the inline script entirely — the bootstrap is the
external static/js/theme-boot.js, Alpine is the @alpinejs/csp build, and every
component is registered from same-origin files. The new guard is strictly
stronger: it covers EVERY template, not one script, and pins the policy itself.

The policy home is the app: `app/main.py:security_headers` emits the canonical CSP
on every response, so the script-src check runs against a real client response —
the actual enforcement surface — rather than grepping config files. The remaining
file scans cover `caddy/headers.caddy` (now a set-if-absent fallback for
Caddy-generated responses) and its Helm ConfigMap mirror.

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
    # The canonical policy home (app-side, #66 inverted).
    _ROOT / "app/main.py",
    # The Caddy fallback and its Helm ConfigMap mirror (Helm can't read files above
    # the chart) — scanned so a hash pin can't linger in either copy.
    _ROOT / "caddy/headers.caddy",
    _ROOT / "helm/iceberg-ebs/templates/caddy-configmap.yaml",
]

# Any <script> tag: must either load a same-origin file (src=) or be a data island
# (type="application/json", inert — never executed).
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.IGNORECASE)


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


async def test_script_src_is_exactly_self(client):
    """Asserted on a real response — the app middleware is the enforcement surface."""
    value = (await client.get("/healthz")).headers["Content-Security-Policy"]
    directives = dict((stripped.split(None, 1) + [""])[:2] for part in value.split(";") if (stripped := part.strip()))
    assert directives.get("script-src") == "'self'", (
        f"script-src must be exactly \"'self'\" (#106) — no hashes, "
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
