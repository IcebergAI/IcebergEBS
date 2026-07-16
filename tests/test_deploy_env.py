"""Regression tests for #87: the deploy stacks forward the tunable env vars.

`.env` is excluded from the image by `.dockerignore`, so a variable an operator sets is only
honoured if the Compose `app.environment` block or the Helm ConfigMap actually forwards it.
These guard against that drift reappearing.
"""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent

# Env vars the stacks must forward (retention/fetch-interval per #87; session/httpx are
# advertised as tunable in README and would otherwise be silently ignored).
_FORWARDED_ENV = [
    "ICEBERG_EBS_RETENTION_DAYS",
    "ICEBERG_EBS_FETCH_INTERVAL_MINUTES",
    "ICEBERG_EBS_SESSION_MAX_AGE",
    "ICEBERG_EBS_HTTPX_TIMEOUT",
    # Rate-limit switches: the edge equivalents of the nginx api/login zones (#188, #196).
    # Login has its own switch so disabling API limiting can't silently drop it.
    "ICEBERG_EBS_API_RATE_LIMIT_ENABLED",
    "ICEBERG_EBS_LOGIN_RATE_LIMIT_ENABLED",
]


def test_compose_app_forwards_expected_env():
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
    env = compose["services"]["app"]["environment"]
    keys = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
    missing = [v for v in _FORWARDED_ENV if v not in keys]
    assert not missing, f"docker-compose app.environment missing: {missing}"


def test_helm_configmap_forwards_expected_env():
    cm = (_ROOT / "helm/iceberg-ebs/templates/configmap.yaml").read_text()
    missing = [v for v in _FORWARDED_ENV if v not in cm]
    assert not missing, f"helm ConfigMap missing: {missing}"


def test_helm_values_declare_forwarded_settings():
    values = yaml.safe_load((_ROOT / "helm/iceberg-ebs/values.yaml").read_text())
    ie = values["icebergEbs"]
    for key in (
        "retentionDays",
        "fetchIntervalMinutes",
        "sessionMaxAge",
        "httpxTimeout",
        "apiRateLimitEnabled",
        "loginRateLimitEnabled",
    ):
        assert key in ie, f"helm values icebergEbs missing: {key}"
