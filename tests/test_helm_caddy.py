"""The Helm Caddy ConfigMap must stay an exact byte-for-byte mirror of the canonical
caddy/ files (#188).

Helm's ``.Files.Get`` cannot read files above the chart directory, so the Kubernetes edge
config is embedded in ``templates/caddy-configmap.yaml`` rather than referenced. That is a
second physical copy of ``caddy/Caddyfile.k8s`` and ``caddy/headers.caddy`` — the exact
kind of duplication #188 set out to kill. These tests make the copy safe: they compare each
embedded block scalar byte-for-byte with its canonical file, so any drift — a reordered,
removed, duplicated, or stale-extra line — fails, not just a missing line. Edit the caddy/
files and re-mirror; never edit only the ConfigMap.
"""

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_CONFIGMAP = _ROOT / "helm/iceberg-ebs/templates/caddy-configmap.yaml"
# ConfigMap data key -> canonical source file it must mirror.
_MIRROR = {
    "Caddyfile": _ROOT / "caddy/Caddyfile.k8s",
    "headers.caddy": _ROOT / "caddy/headers.caddy",
}


def _configmap_data() -> dict[str, str]:
    """Parse the ConfigMap's ``data`` block. The metadata carries Helm ``{{ }}`` expressions
    that break a raw YAML parse, so substitute the two known ones for placeholders first; the
    ``data:`` block scalars are pure literal and untouched."""
    text = _CONFIGMAP.read_text()
    text = text.replace('{{ include "iceberg-ebs.fullname" . }}', "rel")
    # The labels line is a whole templated map entry — replace it with a concrete one.
    text = re.sub(r'\{\{-?\s*include "iceberg-ebs\.labels".*?\}\}', "app.kubernetes.io/name: rel", text)
    doc = yaml.safe_load(text)
    return doc["data"]


def test_configmap_mirrors_canonical_caddy_files_byte_for_byte():
    data = _configmap_data()
    for key, path in _MIRROR.items():
        assert key in data, f"ConfigMap data is missing the {key!r} key"
        # YAML's `|` clip returns the block content with the leading indent stripped and a
        # single trailing newline; the canonical file also ends with one newline.
        assert data[key].rstrip("\n") == path.read_text().rstrip("\n"), (
            f"ConfigMap {key!r} block drifted from {path.relative_to(_ROOT)} — edit the "
            f"canonical file and re-mirror the ConfigMap (never edit only the ConfigMap)."
        )


def test_k8s_caddyfile_uses_strict_trusted_proxies():
    """The K8s sidecar trusts the cluster ingress's X-Forwarded-For, so it MUST use strict
    parsing — otherwise a forged leftmost XFF entry can become the client IP the app's
    per-IP rate limiters key on (#77). Guard against the directive being dropped."""
    k8s = (_ROOT / "caddy/Caddyfile.k8s").read_text()
    assert "trusted_proxies static private_ranges" in k8s
    assert "trusted_proxies_strict" in k8s
    # And the mirror carries it too.
    assert "trusted_proxies_strict" in _configmap_data()["Caddyfile"]


def test_headers_caddy_defers_header_ops():
    """The fallback header block must carry an explicit `defer` so its `?` (set-if-absent) ops
    run AFTER reverse_proxy copies the upstream (app canonical) response headers — that ordering
    is what lets `?` see the app's headers and stand down. Without it the fallback CSP would be
    set first and the app's canonical CSP copied in afterwards: two CSP values, and the browser
    enforces the intersection (the fallback's default-src 'none'), breaking every page (#201).
    The block also defers implicitly via the `-Server` delete op, but that's fragile; the
    explicit `defer` guards a future edit dropping it. Checked in the canonical file and
    enforced identically in the byte-mirrored ConfigMap."""
    canonical = (_ROOT / "caddy/headers.caddy").read_text()
    assert re.search(r"header\s*\{\s*defer\b", canonical), "explicit `defer` missing from headers.caddy header block"
    # The mirror test above already pins byte-equality; this asserts the mirror carries it too.
    assert "defer" in _configmap_data()["headers.caddy"]


def test_ingress_has_no_nonfunctional_hsts_annotation():
    """`nginx.ingress.kubernetes.io/hsts` is NOT a real ingress-nginx annotation — HSTS is a
    controller-wide ConfigMap setting, so the annotation was silently ignored (#201). Guard
    against it being re-added as a misleading no-op. (Only matches a real annotation key line,
    not the explanatory comment that names it.)"""
    ingress = (_ROOT / "helm/iceberg-ebs/templates/ingress.yaml").read_text()
    assert not re.search(r"^\s*nginx\.ingress\.kubernetes\.io/hsts\s*:", ingress, re.MULTILINE)


def test_helm_caddy_tag_matches_compose():
    """The Helm Caddy sidecar image must stay pinned to the same version as the Compose Caddy
    image (#200). Dependabot's `docker-compose` ecosystem bumps the Compose image but cannot
    see Helm `values.yaml`, so without this guard the two documented production paths silently
    drift onto different (CVE-accumulating) edge-proxy versions. When Dependabot bumps Compose,
    this fails until the Helm tag is bumped to match in the same PR."""
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
    compose_image = compose["services"]["caddy"]["image"]  # e.g. "caddy:2.11-alpine"

    values = yaml.safe_load((_ROOT / "helm/iceberg-ebs/values.yaml").read_text())
    helm_img = values["caddy"]["image"]
    helm_image = f"{helm_img['repository']}:{helm_img['tag']}"

    assert helm_image == compose_image, (
        f"Helm Caddy image {helm_image!r} drifted from the Compose Caddy image {compose_image!r} "
        f"— bump helm/iceberg-ebs/values.yaml caddy.image.tag to match (#200)."
    )
