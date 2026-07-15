"""Regression tests for #86: the Compose stack ships an automatic pg_dump backup service."""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE = _ROOT / "docker-compose.yml"
_DEPLOYMENT = _ROOT / "DEPLOYMENT.md"


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


def test_restore_docs_use_container_side_expansion():
    # Compose reads .env but doesn't export it to the invoking shell, so $POSTGRES_USER /
    # $POSTGRES_DB must be expanded inside the container (single-quoted `sh -c`), not by the
    # host shell where they'd be empty. Also stop the backup service during a restore.
    doc = _DEPLOYMENT.read_text()
    assert 'sh -c \'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB"' in doc
    assert 'sh -c \'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' in doc
    assert "docker compose stop app backup" in doc
