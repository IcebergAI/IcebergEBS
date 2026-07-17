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
    # …and their rate/burst tuning knobs, so an operator setting them isn't silently ignored (#202).
    "ICEBERG_EBS_API_RATE_LIMIT_PER_MINUTE",
    "ICEBERG_EBS_API_RATE_LIMIT_BURST",
    "ICEBERG_EBS_LOGIN_RATE_LIMIT_PER_MINUTE",
    "ICEBERG_EBS_LOGIN_RATE_LIMIT_BURST",
    # Outbound-proxy routing trio (#216). Credentials are deliberately NOT here:
    # they are secrets and must not land in the Helm ConfigMap (see the dedicated
    # credential tests below).
    "ICEBERG_EBS_PROXY_MODE",
    "ICEBERG_EBS_PROXY_URL",
    "ICEBERG_EBS_PROXY_NO_PROXY",
]

_PROXY_CREDENTIAL_ENV = ["ICEBERG_EBS_PROXY_USERNAME", "ICEBERG_EBS_PROXY_PASSWORD"]


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
        "apiRateLimitPerMinute",
        "apiRateLimitBurst",
        "loginRateLimitPerMinute",
        "loginRateLimitBurst",
        "proxyMode",
        "proxyUrl",
        "proxyNoProxy",
        "proxyUsername",
        "proxyPassword",
    ):
        assert key in ie, f"helm values icebergEbs missing: {key}"


def test_compose_forwards_proxy_credentials():
    # Credentials must reach the container too — but through the environment,
    # which for Compose is the same passthrough block as the routing trio.
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
    env = compose["services"]["app"]["environment"]
    keys = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}
    missing = [v for v in _PROXY_CREDENTIAL_ENV if v not in keys]
    assert not missing, f"docker-compose app.environment missing: {missing}"


def test_helm_proxy_credentials_stay_out_of_configmap():
    """The proxy credentials are secrets: wired as secretKeyRef in the Deployment,
    never as ConfigMap data (which is world-readable to anyone who can get the CM)."""
    cm = (_ROOT / "helm/iceberg-ebs/templates/configmap.yaml").read_text()
    leaked = [v for v in _PROXY_CREDENTIAL_ENV if v in cm]
    assert not leaked, f"proxy credentials must not be in the ConfigMap: {leaked}"

    deployment = (_ROOT / "helm/iceberg-ebs/templates/deployment.yaml").read_text()
    missing = [v for v in _PROXY_CREDENTIAL_ENV if v not in deployment]
    assert not missing, f"helm Deployment missing secretKeyRef wiring for: {missing}"

    secret = (_ROOT / "helm/iceberg-ebs/templates/secret.yaml").read_text()
    for key in ("proxy-username", "proxy-password"):
        assert key in secret, f"helm Secret missing key: {key}"
