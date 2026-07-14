"""The CSP script hash must match the inline script it is supposed to allow.

The anti-flash theme script is inlined in `base.html` and `login.html` (it must run
before first paint, so it cannot be an external file). A strict CSP therefore pins its
SHA-256 — and that pin is duplicated in **two** deployment paths:

* `nginx/security_headers.conf` (Docker Compose)
* `helm/iceberg-ebs/templates/ingress.yaml` (Kubernetes)

Nothing at runtime notices when a pin drifts from the script: the browser silently
refuses to execute it and the persisted light/dark choice stops being applied. Both
copies had in fact drifted apart before these tests existed — the Helm ingress pinned a
hash that matched neither template. These tests fail loudly instead.
"""

import base64
import hashlib
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = [_ROOT / "app/templates/base.html", _ROOT / "app/templates/login.html"]
_CSP_FILES = [
    _ROOT / "nginx/security_headers.conf",
    _ROOT / "helm/iceberg-ebs/templates/ingress.yaml",
]

_INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)


def _inline_script(template: Path) -> str:
    """The exact bytes between the <script> tags — what the CSP hash is computed over."""
    match = _INLINE_SCRIPT.search(template.read_text(encoding="utf-8"))
    assert match, f"no inline <script> found in {template.name}"
    return match.group(1)


def _sha256(body: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()


def test_inline_script_identical_across_templates():
    """One hash covers both templates only if the script is byte-identical in each."""
    bodies = {t.name: _inline_script(t) for t in _TEMPLATES}
    assert len(set(bodies.values())) == 1, f"inline script differs between templates: {bodies}"


@pytest.mark.parametrize("csp_file", _CSP_FILES, ids=lambda p: p.name)
def test_csp_pins_the_actual_script_hash(csp_file: Path):
    expected = _sha256(_inline_script(_TEMPLATES[0]))
    pinned = re.findall(r"sha256-[A-Za-z0-9+/=]+", csp_file.read_text(encoding="utf-8"))

    assert pinned, f"no sha256- pin found in {csp_file}"
    assert expected in pinned, (
        f"{csp_file} pins {pinned}, but the inline script hashes to {expected}. "
        f"The CSP would block the script it is meant to allow — recompute the hash "
        f"(see docs in DEPLOYMENT.md) and update every CSP copy."
    )
