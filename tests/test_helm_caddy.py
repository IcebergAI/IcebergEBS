"""The Helm Caddy ConfigMap must stay an exact mirror of the canonical caddy/ files (#188).

Helm's ``.Files.Get`` cannot read files above the chart directory, so the Kubernetes edge
config is embedded in ``templates/caddy-configmap.yaml`` rather than referenced. That is a
second physical copy of ``caddy/Caddyfile.k8s`` and ``caddy/headers.caddy`` — the exact
kind of duplication #188 set out to kill. These tests make the copy safe: they fail if the
ConfigMap drifts from the canonical files, so the "single logical source" holds even though
Helm forces a second physical copy. Edit the caddy/ files and re-mirror; never edit only
the ConfigMap.
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CONFIGMAP = _ROOT / "helm/iceberg-ebs/templates/caddy-configmap.yaml"
_CANONICAL = {
    "caddy/Caddyfile.k8s": _ROOT / "caddy/Caddyfile.k8s",
    "caddy/headers.caddy": _ROOT / "caddy/headers.caddy",
}


def test_configmap_mirrors_canonical_caddy_files():
    """Every non-blank line of each canonical file appears in the ConfigMap. The YAML block
    scalar prefixes each line with a fixed space indent, so the original (tab-indented) line
    remains a substring — a mismatch means the mirror drifted."""
    cm = _CONFIGMAP.read_text()
    for name, path in _CANONICAL.items():
        for line in path.read_text().splitlines():
            if line.strip():
                assert line in cm, f"{name} line not mirrored in the Caddy ConfigMap: {line!r}"


def test_configmap_carries_the_canonical_csp():
    """The security-critical invariant: the ConfigMap's CSP is byte-identical to the one in
    caddy/headers.caddy (so K8s and Compose enforce the same policy)."""
    import re

    canonical = re.search(r'Content-Security-Policy "([^"]*)"', _CANONICAL["caddy/headers.caddy"].read_text())
    assert canonical, "no CSP found in caddy/headers.caddy"
    assert canonical.group(1) in _CONFIGMAP.read_text(), "ConfigMap CSP drifted from caddy/headers.caddy"
