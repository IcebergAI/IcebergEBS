from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    admin_username: str
    admin_password: SecretStr
    secret_key: SecretStr
    database_url: str = "postgresql+asyncpg://iceberg_ebs:iceberg_ebs@localhost:5432/iceberg_ebs"
    session_cookie_name: str = "iceberg_ebs_session"
    session_max_age: int = 86400
    secure_cookies: bool = True
    fetch_interval_minutes: int = 60
    httpx_timeout: float = 15.0
    # Data retention: prune FetchLog / InstallCountHistory / AlertLog rows older
    # than this many days. 0 (default) disables pruning entirely. The scheduler
    # runs the prune job daily when enabled (see app/retention.py).
    retention_days: int = 0
    # Minimum seconds between ApiKey.last_used_at writes. Throttles the per-request
    # write so read-only bearer GETs don't commit on every call (a wasted round-trip
    # + row update under the scheduler's concurrent load) — see require_api_auth.
    api_key_last_used_throttle_seconds: int = 60
    # App-level login throttling (defense-in-depth, independent of the reverse proxy).
    login_max_attempts: int = 5
    login_attempt_window_seconds: int = 300
    login_lockout_seconds: int = 300
    app_base_url: str = ""  # e.g. "https://icebergebs.example.com" — used in webhook payloads

    model_config = SettingsConfigDict(env_file=".env", env_prefix="ICEBERG_EBS_")


settings = Settings()
