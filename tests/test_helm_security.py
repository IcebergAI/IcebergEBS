"""Regression tests for #104: the Helm chart keeps the Pod Security 'restricted' baseline."""

from pathlib import Path

_TEMPLATES = Path(__file__).resolve().parent.parent / "helm" / "iceberg-ebs" / "templates"


def test_deployment_has_pod_security_baseline():
    d = (_TEMPLATES / "deployment.yaml").read_text()
    assert "seccompProfile" in d and "RuntimeDefault" in d
    assert "automountServiceAccountToken: false" in d
    # Pre-existing controls that must not regress.
    assert "runAsNonRoot: true" in d
    assert "readOnlyRootFilesystem: true" in d
    assert "allowPrivilegeEscalation: false" in d
    assert "drop: [ALL]" in d


def test_pod_disruption_budget_present():
    p = (_TEMPLATES / "pdb.yaml").read_text()
    assert "kind: PodDisruptionBudget" in p
    assert "maxUnavailable: 0" in p
