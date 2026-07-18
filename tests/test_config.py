"""Settings loading regressions (app/config.py)."""

import os
from pathlib import Path

from app.config import Settings

_REPO = Path(__file__).resolve().parents[1]


def _uncommented_env_example() -> str:
    """The KEY=VALUE lines an operator actually gets by following .env.example —
    comments and blanks stripped. Includes the Compose stack's non-prefixed
    POSTGRES_* keys, which is the crux of #214."""
    lines = []
    for raw in (_REPO / ".env.example").read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            lines.append(stripped)
    return "\n".join(lines) + "\n"


def test_settings_loads_documented_env_example_shape(tmp_path, monkeypatch):
    """Following .env.example (which tells operators to set POSTGRES_DB/USER/PASSWORD in
    the shared .env) must not crash Settings with extra_forbidden (#214). Those keys have
    no ICEBERG_EBS_ prefix, so pydantic-settings treated them as forbidden extras before
    extra="ignore"."""
    env_body = _uncommented_env_example()
    assert "POSTGRES_DB=" in env_body  # guard the fixture actually exercises the bug
    env_file = tmp_path / ".env"
    env_file.write_text(env_body, encoding="utf-8")

    # Clear prefixed env so the file is the source of the required fields, mirroring a
    # fresh host that only has the .env (conftest seeds ICEBERG_EBS_* into os.environ).
    for key in [k for k in os.environ if k.startswith("ICEBERG_EBS_")]:
        monkeypatch.delenv(key, raising=False)

    settings = Settings(_env_file=str(env_file))

    # Constructed without raising, and the non-prefixed POSTGRES_* keys were ignored,
    # not adopted as attributes.
    assert settings.admin_username == "admin"
    assert not hasattr(settings, "postgres_db")


def test_settings_ignores_unknown_prefixed_key(tmp_path):
    """extra="ignore" also drops an unknown ICEBERG_EBS_* key rather than crashing. This
    is the documented trade-off (a typo'd key is silently ignored, not a hard error) —
    pinned so a future change back to extra="forbid" is a conscious decision (#214)."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ICEBERG_EBS_ADMIN_USERNAME=a\n"
        "ICEBERG_EBS_ADMIN_PASSWORD=b\n"
        "ICEBERG_EBS_SECRET_KEY=" + "x" * 32 + "\n"
        "ICEBERG_EBS_DEFINITELY_NOT_A_FIELD=1\n",
        encoding="utf-8",
    )
    # Does not raise.
    Settings(_env_file=str(env_file))
