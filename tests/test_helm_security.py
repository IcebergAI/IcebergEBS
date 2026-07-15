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


def test_deployment_uses_recreate_strategy_for_singleton():
    # A PDB only governs voluntary evictions; a rolling update with replicas=1 could
    # still surge to two pods and run two schedulers. Recreate closes that window (#104).
    d = (_TEMPLATES / "deployment.yaml").read_text()
    assert "strategy:" in d
    assert "type: Recreate" in d
