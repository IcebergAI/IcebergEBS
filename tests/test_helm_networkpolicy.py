"""Regression tests for #103: the Helm chart ships NetworkPolicies (default-deny + hops)."""

from pathlib import Path

import yaml

_CHART = Path(__file__).resolve().parent.parent / "helm" / "iceberg-ebs"
_NP = _CHART / "templates" / "networkpolicy.yaml"


def test_networkpolicy_template_present():
    assert _NP.exists()


def test_networkpolicy_default_deny_and_hops():
    t = _NP.read_text()
    assert "kind: NetworkPolicy" in t
    # default-deny ingress for the whole namespace
    assert "default-deny-ingress" in t and "podSelector: {}" in t
    # explicit hops: ingress → the pod's Caddy sidecar on 8080 (#188), app → postgres 5432
    assert "allow-app-from-ingress" in t and "port: 8080" in t
    assert "allow-postgres-from-app" in t and "port: 5432" in t
    # gated + egress left open (no Egress policy type in any policy)
    assert "if .Values.networkPolicy.enabled" in t
    assert "- Egress" not in t


def test_no_second_policy_can_re_open_postgres():
    # K8s unions ingress across every policy selecting a pod, so a *second*, more
    # permissive NetworkPolicy re-opens Postgres regardless of our app-only rule —
    # the union can only add access, never revoke it (#103). This used to mean
    # disabling the Bitnami subchart's own default-permissive policy via
    # `postgresql.networkPolicy.enabled: false`. Since #276 there is no subchart:
    # this chart owns every manifest, so the guard is that our rule is the only
    # policy selecting the DB pods.
    values = yaml.safe_load((_CHART / "values.yaml").read_text())
    assert "networkPolicy" not in values["postgresql"], (
        "postgresql.networkPolicy is a leftover of the removed Bitnami subchart; "
        "an inert value here would read as protection that isn't there"
    )

    policies = [doc for doc in (_CHART / "templates").glob("*.yaml") if "kind: NetworkPolicy" in doc.read_text()]
    assert policies == [_CHART / "templates/networkpolicy.yaml"], (
        "NetworkPolicies must live in one file; a policy elsewhere could union in "
        "extra ingress to Postgres without this test noticing"
    )


def test_postgres_ingress_rule_selects_the_bundled_db_pods():
    # A podSelector that matches nothing leaves Postgres with no policy at all,
    # which — with a default-deny in place — looks identical to "protected" in a
    # values file but is not (#276).
    policy = (_CHART / "templates/networkpolicy.yaml").read_text()
    helpers = (_CHART / "templates/_helpers.tpl").read_text()
    assert 'include "iceberg-ebs.postgresql.selectorLabels"' in policy
    assert '{{- define "iceberg-ebs.postgresql.selectorLabels" -}}' in helpers
    # The same helper must label the StatefulSet's pod template.
    assert 'include "iceberg-ebs.postgresql.selectorLabels"' in (_CHART / "templates/postgres.yaml").read_text()
