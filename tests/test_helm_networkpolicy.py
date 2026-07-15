"""Regression tests for #103: the Helm chart ships NetworkPolicies (default-deny + hops)."""

from pathlib import Path

_NP = Path(__file__).resolve().parent.parent / "helm" / "iceberg-ebs" / "templates" / "networkpolicy.yaml"


def test_networkpolicy_template_present():
    assert _NP.exists()


def test_networkpolicy_default_deny_and_hops():
    t = _NP.read_text()
    assert "kind: NetworkPolicy" in t
    # default-deny ingress for the whole namespace
    assert "default-deny-ingress" in t and "podSelector: {}" in t
    # explicit hops
    assert "allow-app-from-ingress" in t and "port: 8000" in t
    assert "allow-postgres-from-app" in t and "port: 5432" in t
    # gated + egress left open (no Egress policy type in any policy)
    assert "if .Values.networkPolicy.enabled" in t
    assert "- Egress" not in t
