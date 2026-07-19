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
    # SSO sessions expire faster than local ones (#221): an IdP-side disable/reset
    # can't be pushed to us, so a short lifetime forces re-authentication through the
    # IdP — which fails for a disabled account — bounding how long a stale SSO session
    # (or a stolen cookie) survives. Local password sessions keep session_max_age.
    oidc_session_max_age: int = 3600
    # Holds the IdP's id_token as the id_token_hint for RP-initiated logout (#221);
    # HttpOnly, set at OIDC login, cleared on logout.
    oidc_id_token_cookie_name: str = "iceberg_ebs_idt"
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
    # Outbound proxy (#216). These SEED the admin-editable ProxySettings row on first
    # read (app/proxy_settings.py); after that the row is the source of truth for
    # routing, editable live at /admin/proxy. Modes: system (honour HTTP(S)_PROXY /
    # ALL_PROXY / NO_PROXY env — parsed by app/proxy.py, since httpx's trust_env can't
    # do it through a custom transport), none (always direct), explicit (use proxy_url
    # unless the target matches proxy_no_proxy). Credentials are env-ONLY: never
    # persisted to the DB, never returned by the API, never logged.
    proxy_mode: str = "system"  # system | none | explicit
    proxy_url: str = ""  # scheme://host:port — no credentials here
    proxy_no_proxy: str = "localhost,127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1"
    proxy_username: str = ""  # SECRET: env-only
    proxy_password: SecretStr = SecretStr("")  # SECRET: env-only
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
    # Maximum age of an API key owned by an SSO account, in days (#278). An IdP-side
    # disable can't be pushed to us and the offboarded user never logs in again, so
    # nothing app-side would ever revoke their keys — a bounded lifetime is the same
    # containment #221 applies to SSO cookies, scaled for M2M use. <= 0 disables.
    api_key_sso_max_age_days: int = 30
    # Freshness window for SOAR install observations, in days (#287): an observation
    # whose last_seen is older stops counting toward install_footprint (and exposure),
    # so an extension removed from every endpoint decays instead of staying inflated
    # forever. <= 0 disables decay (count all observations ever).
    inventory_freshness_days: int = 30
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
    # SSO / OIDC (#32). Non-secret fields SEED the admin-editable OIDCSettings row
    # on first read (app/oidc_settings.py); after that the row is the source of
    # truth, editable live at /admin/oidc. auth_mode gates the two login paths:
    # local (password only), oidc (SSO only — refused unless a complete provider is
    # enabled, so a bad config can't lock everyone out), both (default). Client
    # secrets are env-ONLY: never persisted to the DB, never returned by the API,
    # never logged (same rule as the proxy credentials above).
    auth_mode: str = "both"  # local | oidc | both
    # Absolute public base URL for the IdP redirect back (e.g. "https://ebs.example.com")
    # for proxy deployments where the app-observed host/scheme differs from the
    # browser's. Empty ⇒ derive the callback URL from the request.
    oidc_redirect_base_url: str = ""
    # Microsoft Entra ID. tenant_id MUST be a specific tenant (GUID or verified
    # domain) — never "common"/"organizations" — so ID-token issuer validation is exact.
    oidc_entra_enabled: bool = False
    oidc_entra_client_id: str = ""
    oidc_entra_client_secret: SecretStr = SecretStr("")  # SECRET: env-only
    oidc_entra_tenant_id: str = ""
    oidc_entra_scopes: str = "openid email profile"
    oidc_entra_role_claim: str = ""
    oidc_entra_role_map: str = ""  # "group=admin,group2=user" allowlist
    # Authentik (self-hostable; the e2e test target). Discovery is derived from
    # base_url + app_slug: {base}/application/o/{slug}/.well-known/openid-configuration
    oidc_authentik_enabled: bool = False
    oidc_authentik_client_id: str = ""
    oidc_authentik_client_secret: SecretStr = SecretStr("")  # SECRET: env-only
    oidc_authentik_base_url: str = ""
    oidc_authentik_app_slug: str = ""
    oidc_authentik_scopes: str = "openid email profile"
    oidc_authentik_role_claim: str = "groups"
    oidc_authentik_role_map: str = ""
    # Auth0. Roles/groups need a namespaced custom claim (Action/Rule) — point
    # role_claim at it.
    oidc_auth0_enabled: bool = False
    oidc_auth0_client_id: str = ""
    oidc_auth0_client_secret: SecretStr = SecretStr("")  # SECRET: env-only
    oidc_auth0_domain: str = ""
    oidc_auth0_scopes: str = "openid email profile"
    oidc_auth0_role_claim: str = ""
    oidc_auth0_role_map: str = ""
    # Okta. auth_server "" = the org authorization server; set it (often "default")
    # for a custom authorization server at /oauth2/<server>/.
    oidc_okta_enabled: bool = False
    oidc_okta_client_id: str = ""
    oidc_okta_client_secret: SecretStr = SecretStr("")  # SECRET: env-only
    oidc_okta_domain: str = ""
    oidc_okta_auth_server: str = ""
    oidc_okta_scopes: str = "openid email profile"
    oidc_okta_role_claim: str = "groups"
    oidc_okta_role_map: str = ""
    app_base_url: str = ""  # e.g. "https://icebergebs.example.com" — used in webhook payloads
    # Emit logs as single-line JSON (for a log collector) instead of timestamped text (#89).
    log_json: bool = False
    # Comma-separated extra origins allowed by the CSRF origin check (#107), for proxy
    # deployments that rewrite Host so the app-observed origin differs from the browser's.
    # Same-origin requests are always allowed with no configuration.
    trusted_origins: str = ""

    # extra="ignore" so the shared .env (which .env.example tells operators to fill
    # with the Compose stack's POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD) doesn't
    # crash app startup: without it pydantic-settings treats every non-ICEBERG_EBS_ key
    # in the dotenv as a forbidden extra (#214). The ICEBERG_EBS_ prefix is deliberately
    # shared with consumers outside this class — the per-provider OIDC secrets are read
    # straight from os.environ in app/oidc/config.py — so this class can't own an
    # exhaustive "known keys" set anyway.
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ICEBERG_EBS_", extra="ignore")

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
