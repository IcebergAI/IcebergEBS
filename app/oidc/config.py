"""Pure OIDC configuration model + validation (#32).

The runtime config is a frozen snapshot of the admin-editable, non-secret SSO
fields (mirroring the #216 proxy pattern): env vars seed the DB singleton on
first read, after which the row is the source of truth. This module is
DB-free — ``app/oidc_settings.py`` owns the row and the in-memory snapshot;
``app/oidc/service.py`` consumes ``enabled_providers()`` to register Authlib
clients. Client secrets are env-only and are read here (never stored) when
building a provider config or reporting set/unset status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.config import settings

AUTH_MODE_LOCAL = "local"
AUTH_MODE_OIDC = "oidc"
AUTH_MODE_BOTH = "both"
AUTH_MODES = (AUTH_MODE_LOCAL, AUTH_MODE_OIDC, AUTH_MODE_BOTH)

# Provider keys shipped with adapters. The registry in app/oidc/base.py maps
# these to adapter implementations (registered at import in app/oidc/service.py).
PROVIDER_KEYS = ("entra", "authentik", "auth0", "okta")

# role_map values an IdP group may map to. "admin" grants is_admin; "user" is an
# explicit non-admin mapping. Widens to the role enum when RBAC lands (#33) —
# which is also why the User provenance column is named role_managed_by_idp.
ROLE_MAP_VALUES = ("admin", "user")

# Fields an admin may change (also the OIDCRuntimeConfig field list). Client
# secrets are intentionally absent — they are env-only and never reach the DB.
EDITABLE_FIELDS = (
    "auth_mode",
    "oidc_redirect_base_url",
    "oidc_entra_enabled",
    "oidc_entra_client_id",
    "oidc_entra_tenant_id",
    "oidc_entra_scopes",
    "oidc_entra_role_claim",
    "oidc_entra_role_map",
    "oidc_authentik_enabled",
    "oidc_authentik_client_id",
    "oidc_authentik_base_url",
    "oidc_authentik_app_slug",
    "oidc_authentik_scopes",
    "oidc_authentik_role_claim",
    "oidc_authentik_role_map",
    "oidc_auth0_enabled",
    "oidc_auth0_client_id",
    "oidc_auth0_domain",
    "oidc_auth0_scopes",
    "oidc_auth0_role_claim",
    "oidc_auth0_role_map",
    "oidc_okta_enabled",
    "oidc_okta_client_id",
    "oidc_okta_domain",
    "oidc_okta_auth_server",
    "oidc_okta_scopes",
    "oidc_okta_role_claim",
    "oidc_okta_role_map",
)


@dataclass(frozen=True)
class OIDCProviderConfig:
    """Resolved config for one enabled OIDC provider."""

    key: str
    display_name: str
    client_id: str
    client_secret: str
    metadata_url: str
    scopes: str = "openid email profile"
    # Optional group claim → is_admin allowlist. Empty ⇒ nobody is elevated
    # (no self-elevation).
    role_claim: str = ""
    role_map: dict[str, str] = field(default_factory=dict)


def _parse_role_map(raw: str) -> dict[str, str]:
    """Parse a "group=admin,group2=user" allowlist into a dict.

    Unknown values are dropped where the map is applied (service.map_is_admin);
    validate_config rejects them up front for admin-visible feedback.
    """
    result: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        group, role = (p.strip() for p in pair.split("=", 1))
        if group and role:
            result[group] = role
    return result


@dataclass(frozen=True)
class OIDCRuntimeConfig:
    auth_mode: str
    oidc_redirect_base_url: str
    oidc_entra_enabled: bool
    oidc_entra_client_id: str
    oidc_entra_tenant_id: str
    oidc_entra_scopes: str
    oidc_entra_role_claim: str
    oidc_entra_role_map: str
    oidc_authentik_enabled: bool
    oidc_authentik_client_id: str
    oidc_authentik_base_url: str
    oidc_authentik_app_slug: str
    oidc_authentik_scopes: str
    oidc_authentik_role_claim: str
    oidc_authentik_role_map: str
    oidc_auth0_enabled: bool
    oidc_auth0_client_id: str
    oidc_auth0_domain: str
    oidc_auth0_scopes: str
    oidc_auth0_role_claim: str
    oidc_auth0_role_map: str
    oidc_okta_enabled: bool
    oidc_okta_client_id: str
    oidc_okta_domain: str
    oidc_okta_auth_server: str
    oidc_okta_scopes: str
    oidc_okta_role_claim: str
    oidc_okta_role_map: str

    @property
    def local_auth_enabled(self) -> bool:
        return self.auth_mode in (AUTH_MODE_LOCAL, AUTH_MODE_BOTH)

    @property
    def oidc_auth_enabled(self) -> bool:
        return self.auth_mode in (AUTH_MODE_OIDC, AUTH_MODE_BOTH)

    def enabled_providers(self) -> list[OIDCProviderConfig]:
        if not self.oidc_auth_enabled:
            return []
        providers: list[OIDCProviderConfig] = []
        if self.oidc_entra_enabled:
            # The tenant-pinned authority: Authlib validates the ID token's issuer
            # against this discovery document, so a concrete tenant here is what
            # makes issuer validation exact (see validate_config's alias check).
            authority = f"https://login.microsoftonline.com/{self.oidc_entra_tenant_id}/v2.0"
            providers.append(
                OIDCProviderConfig(
                    key="entra",
                    display_name="Microsoft Entra ID",
                    client_id=self.oidc_entra_client_id,
                    client_secret=settings.oidc_entra_client_secret.get_secret_value(),
                    metadata_url=f"{authority}/.well-known/openid-configuration",
                    scopes=self.oidc_entra_scopes,
                    role_claim=self.oidc_entra_role_claim,
                    role_map=_parse_role_map(self.oidc_entra_role_map),
                )
            )
        if self.oidc_authentik_enabled:
            base = self.oidc_authentik_base_url.rstrip("/")
            providers.append(
                OIDCProviderConfig(
                    key="authentik",
                    display_name="Authentik",
                    client_id=self.oidc_authentik_client_id,
                    client_secret=settings.oidc_authentik_client_secret.get_secret_value(),
                    metadata_url=(
                        f"{base}/application/o/{self.oidc_authentik_app_slug}/.well-known/openid-configuration"
                    ),
                    scopes=self.oidc_authentik_scopes,
                    role_claim=self.oidc_authentik_role_claim,
                    role_map=_parse_role_map(self.oidc_authentik_role_map),
                )
            )
        if self.oidc_auth0_enabled:
            domain = self.oidc_auth0_domain.rstrip("/")
            providers.append(
                OIDCProviderConfig(
                    key="auth0",
                    display_name="Auth0",
                    client_id=self.oidc_auth0_client_id,
                    client_secret=settings.oidc_auth0_client_secret.get_secret_value(),
                    metadata_url=f"https://{domain}/.well-known/openid-configuration",
                    scopes=self.oidc_auth0_scopes,
                    role_claim=self.oidc_auth0_role_claim,
                    role_map=_parse_role_map(self.oidc_auth0_role_map),
                )
            )
        if self.oidc_okta_enabled:
            domain = self.oidc_okta_domain.rstrip("/")
            server = self.oidc_okta_auth_server.strip("/")
            path = f"/oauth2/{server}" if server else ""
            providers.append(
                OIDCProviderConfig(
                    key="okta",
                    display_name="Okta",
                    client_id=self.oidc_okta_client_id,
                    client_secret=settings.oidc_okta_client_secret.get_secret_value(),
                    metadata_url=f"https://{domain}{path}/.well-known/openid-configuration",
                    scopes=self.oidc_okta_scopes,
                    role_claim=self.oidc_okta_role_claim,
                    role_map=_parse_role_map(self.oidc_okta_role_map),
                )
            )
        return providers


def env_config() -> OIDCRuntimeConfig:
    """The env-seeded runtime config (used before/without the DB row)."""
    return OIDCRuntimeConfig(**{f: getattr(settings, f) for f in EDITABLE_FIELDS})


def client_secret_status() -> dict[str, bool]:
    """Which providers have a client secret set in the environment (never the values)."""
    return {key: bool(getattr(settings, f"oidc_{key}_client_secret").get_secret_value()) for key in PROVIDER_KEYS}


def _valid_absolute_url(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _validate_role_map(provider: str, raw: str) -> None:
    if not raw.strip():
        return
    parsed = _parse_role_map(raw)
    pairs = [pair.strip() for pair in raw.split(",") if pair.strip()]
    if (
        len(parsed) != len(pairs)
        or any("=" not in pair for pair in pairs)
        or any(role not in ROLE_MAP_VALUES for role in parsed.values())
    ):
        raise ValueError(f"{provider} role map must use group={'|'.join(ROLE_MAP_VALUES)} pairs")


def validate_config(config: OIDCRuntimeConfig) -> None:
    """Reject an unusable SSO config. Raises ValueError with an admin-facing message.

    Runs at startup (fail-fast/fail-closed via oidc_settings.refresh_cache) and on
    every admin save. The last check is the lockout guard: OIDC-only mode with no
    complete enabled provider would leave no way to sign in at all.
    """
    if config.auth_mode not in AUTH_MODES:
        raise ValueError("Authentication mode must be local, oidc, or both")
    if config.oidc_redirect_base_url and not _valid_absolute_url(config.oidc_redirect_base_url):
        raise ValueError("OIDC redirect base URL must be an absolute http(s) URL")
    for key in PROVIDER_KEYS:
        _validate_role_map(key, getattr(config, f"oidc_{key}_role_map"))
    if not config.oidc_auth_enabled:
        return

    secrets_set = client_secret_status()
    requirements = {
        "entra": (config.oidc_entra_client_id, config.oidc_entra_tenant_id),
        "authentik": (
            config.oidc_authentik_client_id,
            config.oidc_authentik_base_url,
            config.oidc_authentik_app_slug,
        ),
        "auth0": (config.oidc_auth0_client_id, config.oidc_auth0_domain),
        "okta": (config.oidc_okta_client_id, config.oidc_okta_domain),
    }
    enabled = []
    for key in PROVIDER_KEYS:
        if not getattr(config, f"oidc_{key}_enabled"):
            continue
        enabled.append(key)
        if not all(value.strip() for value in requirements[key]):
            raise ValueError(f"{key} is enabled but its non-secret configuration is incomplete")
        scopes = set(getattr(config, f"oidc_{key}_scopes").split())
        if "openid" not in scopes:
            raise ValueError(f"{key} is enabled but its scopes do not include the required openid scope")
        if not secrets_set[key]:
            raise ValueError(f"ICEBERG_EBS_OIDC_{key.upper()}_CLIENT_SECRET is not set in the environment")
    if config.oidc_entra_enabled and config.oidc_entra_tenant_id.strip().lower() in (
        "common",
        "organizations",
        "consumers",
    ):
        # A multi-tenant authority would accept ID tokens from ANY tenant — issuer
        # validation must pin one concrete tenant.
        raise ValueError(
            "entra tenant_id must be a specific tenant (GUID or verified domain), not a multi-tenant alias"
        )
    if config.auth_mode == AUTH_MODE_OIDC and not enabled:
        raise ValueError("OIDC-only mode requires at least one complete enabled provider; local login was kept on")
