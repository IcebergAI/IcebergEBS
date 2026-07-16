from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# itsdangerous cookie/flash signing is only as strong as secret_key. Reject a
# weak key at startup rather than silently signing sessions with it.
_MIN_SECRET_KEY_LENGTH = 32


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
    # Graceful-shutdown drain window (#109): how long to await an in-flight watchlist refresh
    # before giving up and letting the durable pending-alert marker cover the rest on restart.
    # Keep the container grace period (terminationGracePeriodSeconds / stop_grace_period) above it.
    shutdown_drain_seconds: float = 55.0
    # Outbound-fetch resilience (#108). The shared client retries transient failures
    # (connect/timeout/429/5xx) on idempotent GETs with exponential backoff + jitter,
    # honouring Retry-After; 404 (delisted) is never retried. Limits cap how many
    # connections a large watchlist refresh may open against the stores.
    httpx_max_retries: int = 3
    httpx_backoff_base: float = 0.5
    httpx_backoff_cap: float = 10.0
    httpx_max_connections: int = 20
    httpx_max_keepalive_connections: int = 10
    # Per-store circuit breaker: after this many consecutive failures for one store
    # within a refresh cycle, skip that store's remaining extensions for the rest of
    # the cycle and mark them as a store outage (not an extension fault). 0 disables.
    store_circuit_failure_threshold: int = 5
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
    # App-level API request-rate limiting (#188). This is the edge equivalent of the old
    # nginx `api` limit_req zone (60 req/min, burst 20), moved app-side when the reverse
    # proxy became Caddy — stock Caddy has no rate_limit directive. It's a token bucket
    # keyed on the client IP (the Caddy-set canonical X-Forwarded-For, via uvicorn's
    # --forwarded-allow-ips; the #77 anti-spoof makes that trustworthy). Disabled by
    # default so the test suite — which fires many /api calls per test — isn't throttled;
    # the Compose/Helm production env sets api_rate_limit_enabled=true. In production the
    # cluster ingress also rate-limits at the true edge (belt and suspenders).
    api_rate_limit_enabled: bool = False
    api_rate_limit_per_minute: int = 60
    api_rate_limit_burst: int = 20
    # Per-IP request-rate cap on POST /login (#196). The failure-keyed LoginRateLimiter
    # above only locks a specific (IP, username) pair after N *failures*, so on its own it
    # stops neither username-spraying from one IP nor a bcrypt-cost flood of the login
    # endpoint. This is the edge equivalent of the old nginx `login` limit_req zone
    # (5 req/min, burst 5) that the Caddy migration dropped — a token bucket keyed on the
    # client IP. Its own enable switch, independent of api_rate_limit_enabled (so disabling
    # API limiting can't silently drop login brute-force/DoS protection); defaults off so the
    # test suite's login flows aren't throttled, and the Compose/Helm prod env sets it on.
    login_rate_limit_enabled: bool = False
    login_rate_limit_per_minute: int = 5
    login_rate_limit_burst: int = 5
    app_base_url: str = ""  # e.g. "https://icebergebs.example.com" — used in webhook payloads
    # Emit logs as single-line JSON (for a log collector) instead of timestamped text (#89).
    log_json: bool = False
    # Comma-separated extra origins allowed by the CSRF origin check (#107), for proxy
    # deployments that rewrite Host so the app-observed origin differs from the browser's.
    # Same-origin requests are always allowed with no configuration.
    trusted_origins: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="ICEBERG_EBS_")

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_key_length(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < _MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"ICEBERG_EBS_SECRET_KEY must be at least {_MIN_SECRET_KEY_LENGTH} characters "
                '(generate one with: python -c "import secrets; print(secrets.token_hex(32))")'
            )
        return v


settings = Settings()
