"""Regression tests for #102: the Docker Compose stack stays hardened."""

from pathlib import Path

import yaml

_COMPOSE = yaml.safe_load((Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text())
_SERVICES = _COMPOSE["services"]


def test_app_is_locked_down():
    app = _SERVICES["app"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert app["cap_drop"] == ["ALL"]
    assert app["read_only"] is True
    assert "/tmp" in app["tmpfs"]
    assert "healthcheck" in app


def test_caddy_is_locked_down():
    caddy = _SERVICES["caddy"]
    assert "no-new-privileges:true" in caddy["security_opt"]
    assert caddy["cap_drop"] == ["ALL"]
    assert "NET_BIND_SERVICE" in caddy["cap_add"]
    assert caddy["read_only"] is True
    assert "healthcheck" in caddy


def test_postgres_blocks_privilege_escalation():
    # Postgres keeps its default caps (entrypoint needs them) but must not escalate.
    assert "no-new-privileges:true" in _SERVICES["postgres"]["security_opt"]


def test_caddy_waits_for_app_health():
    assert _SERVICES["caddy"]["depends_on"]["app"]["condition"] == "service_healthy"
