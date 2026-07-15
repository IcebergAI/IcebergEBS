"""Regression tests for #86: the Compose stack ships an automatic pg_dump backup service."""

from pathlib import Path

import yaml

_COMPOSE = Path(__file__).resolve().parent.parent / "docker-compose.yml"


def _services():
    return yaml.safe_load(_COMPOSE.read_text())["services"]


def test_backup_service_present():
    assert "backup" in _services()


def test_backup_uses_same_pinned_image_as_postgres():
    svc = _services()
    # pg_dump's version must match the server's, so reuse the exact pinned server image.
    assert svc["backup"]["image"] == svc["postgres"]["image"]


def test_backup_runs_pg_dump_with_retention_and_atomic_write():
    cmd = " ".join(_services()["backup"]["command"])
    assert "pg_dump" in cmd
    assert "-Fc" in cmd  # custom-format (compressed + selective restore)
    assert ".tmp" in cmd and "mv " in cmd  # atomic: write .tmp then rename
    assert "-mtime" in cmd and "-delete" in cmd  # retention prune
    # Shell vars are $$-escaped so Compose passes them through to the shell, not itself.
    assert "$${BACKUP_RETENTION_DAYS}" in cmd or "$$BACKUP_RETENTION_DAYS" in cmd


def test_backup_waits_for_healthy_postgres():
    dep = _services()["backup"]["depends_on"]["postgres"]
    assert dep["condition"] == "service_healthy"


def test_backup_persists_dumps_to_host():
    assert any(v.endswith(":/backups") for v in _services()["backup"]["volumes"])


def test_backup_is_hardened_like_the_other_services():
    svc = _services()["backup"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["cap_drop"] == ["ALL"]
    assert svc["read_only"] is True


def test_backup_has_db_credentials():
    env = _services()["backup"]["environment"]
    assert "PGPASSWORD" in env
    assert "POSTGRES_USER" in env and "POSTGRES_DB" in env
