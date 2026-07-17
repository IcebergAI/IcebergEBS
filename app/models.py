from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import CheckConstraint, Column, DateTime, Index, desc
from sqlmodel import Field, SQLModel, UniqueConstraint

from app.utils import json_list, json_object


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _tz_column(*, nullable: bool) -> Column[Any]:
    """A timezone-aware timestamp column (Postgres ``timestamptz``).

    All timestamps are stored tz-aware (UTC): the app writes tz-aware datetimes
    (see `_utcnow` / `datetime.now(timezone.utc)`), which a plain
    ``TIMESTAMP WITHOUT TIME ZONE`` column rejects under asyncpg. A fresh Column is
    returned per call because a Column instance binds to a single table.
    """
    return Column(DateTime(timezone=True), nullable=nullable)


class User(SQLModel, table=True):
    # SSO identity (#32): an OIDC account is keyed on the immutable
    # (auth_provider, oidc_subject) pair — never on the mutable email claim.
    # Postgres treats NULL oidc_subject values as distinct, so local rows
    # ("local", NULL) never collide with each other.
    __table_args__ = (UniqueConstraint("auth_provider", "oidc_subject", name="uq_user_provider_subject"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    # NULL for SSO-provisioned accounts: they have no local password and are
    # refused by the password login path (see auth.verify_credentials).
    password_hash: Optional[str] = None
    email: Optional[str] = None
    is_admin: bool = False
    # "local" for password accounts, else the OIDC provider key (#32).
    auth_provider: str = Field(default="local", index=True)
    oidc_subject: Optional[str] = None
    # IdP tenant provenance (Entra `tid`). Immutable once set — a returning login
    # from a different tenant is an identity conflict, not the same account.
    auth_tenant: Optional[str] = None
    # True only for JIT-provisioned SSO accounts: their is_admin flag is re-derived
    # from IdP groups on every login. Locally-created users (incl. the seeded
    # break-glass admin) keep False, so the IdP can never demote them.
    role_managed_by_idp: bool = False
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    # Generic session-revocation cutoff (M1 / #6, widened by #32): bumped on
    # password change AND on an IdP-driven authorization change (is_admin sync).
    # Sessions/cookies signed before this instant are rejected.
    password_changed_at: Optional[datetime] = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=True))


class Extension(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("user_id", "store", "extension_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    # Orphaned (not deleted) when the owner is removed — see delete_user, which also
    # drops them off the watchlist. SET NULL keeps the row + its fetch/alert history.
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", ondelete="SET NULL", index=True)
    store: str  # "chrome" | "vscode" | "edge"
    extension_id: str
    name: str
    publisher: str
    description: Optional[str] = None
    version: str
    install_count: Optional[int] = None
    last_updated: Optional[datetime] = Field(default=None, sa_column=_tz_column(nullable=True))
    permissions: str = "[]"  # JSON-encoded list
    store_url: str
    added_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    last_fetched_at: Optional[datetime] = Field(default=None, sa_column=_tz_column(nullable=True))
    watchlist: bool = True
    risk_score: Optional[int] = None
    risk_detail: Optional[str] = None  # JSON breakdown per signal
    package_analysis: Optional[str] = None  # JSON output from inspector
    # Cached org install footprint = distinct asset count from SOAR inventory (#29),
    # maintained on each /api/inventory upsert. Exposure ("blast radius") is computed
    # downstream as risk_score × install_footprint (never stored).
    install_footprint: Optional[int] = None
    # Change events staged in the SAME commit as a state change, so an alert missed
    # because the process died between the commit and webhook delivery is re-fired on
    # the next scheduler cycle rather than lost (#109). JSON list of
    # {event_type, old_value, new_value}; cleared once fire_alerts has processed them.
    pending_alert_events: Optional[str] = None

    # Typed accessors for the JSON-in-str columns above (#167): each owns the one
    # defensive parse (missing / unparsable / wrong-shape → a safe fallback) so
    # consumers don't re-implement it and can't reintroduce the #17/#61 bug class.
    # Writers still json.dumps the value back onto the column.
    def permissions_list(self) -> list[str]:
        """Stored API permissions as a list of strings; [] when missing/malformed/not a list,
        with non-string members dropped — a wrong-typed member would otherwise 500 the
        ``list[str]`` API DTO and the CSV export's ``";".join(...)`` (#150)."""
        return [p for p in json_list(self.permissions, "permissions", self.id) if isinstance(p, str)]

    def analysis_dict(self) -> dict | None:
        """Stored package_analysis as a dict, or None when absent/malformed/not an object."""
        return json_object(self.package_analysis, "package_analysis", self.id)

    def risk_detail_dict(self) -> dict | None:
        """Stored risk_detail breakdown as a dict, or None when absent/malformed/not an object."""
        return json_object(self.risk_detail, "risk_detail", self.id)

    # The pending_alert_events marker is decoded by services._parse_pending_events, which
    # returns typed ChangeEvents (defined in notifications.py, so it can't live here without
    # a circular import) and drops non-dict *and* malformed-event entries in one place (#197).


class FetchLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id", ondelete="CASCADE", index=True)
    fetched_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    success: bool
    # True when this failure is a *store outage* (the per-store circuit breaker skipped
    # the extension because its store had N consecutive failures this cycle), not the
    # extension itself being broken — so the dashboard's Fetch-health tile doesn't blame
    # the extension for a store being down (#108).
    store_outage: bool = Field(default=False)
    error_message: Optional[str] = None
    risk_score_before: Optional[int] = None
    risk_score_after: Optional[int] = None


class InstallCountHistory(SQLModel, table=True):
    __table_args__ = (
        Index(
            "ix_installcounthistory_extension_recorded_id",
            "extension_id",
            desc("recorded_at"),
            desc("id"),
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id", ondelete="CASCADE", index=True)
    recorded_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    install_count: int


class InstallObservation(SQLModel, table=True):
    # Org install inventory fed from the SOAR (#29). One row per (extension, asset);
    # re-pushing the same pair upserts last_seen. CASCADE removes observations with
    # their parent extension via the schema, like FetchLog / InstallCountHistory.
    __table_args__ = (UniqueConstraint("extension_id", "asset_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id", ondelete="CASCADE", index=True)
    asset_id: str  # endpoint/device identifier from the SOAR
    asset_type: Optional[str] = None  # e.g. "workstation" | "server"
    department: Optional[str] = None  # department / tag
    source: str = "soar"  # which SOAR feed reported it
    first_seen: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    last_seen: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))


class AlertDestination(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)
    label: str
    target: str  # webhook URL
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))


class AlertRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)
    destination_id: int = Field(foreign_key="alertdestination.id", ondelete="CASCADE", index=True)
    extension_id: Optional[int] = Field(default=None, foreign_key="extension.id", ondelete="CASCADE")
    event_type: str  # "risk_level_change" | "publisher_change" | "permission_change" | "new_version"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))


class ApiKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)
    label: str
    key_hash: str = Field(index=True)  # SHA-256 hex of raw key
    key_prefix: str = ""  # first 12 chars of raw key for display
    key_suffix: str = ""  # last 4 chars of raw key for display
    readonly: bool = False
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    last_used_at: Optional[datetime] = Field(default=None, sa_column=_tz_column(nullable=True))


class ProxySettings(SQLModel, table=True):
    # Singleton (id == 1): admin-editable outbound-proxy routing config (#216),
    # seeded from the ICEBERG_EBS_PROXY_* env on first read (app/proxy_settings.py).
    # Holds NO secret — proxy credentials are env-only and injected into the proxy
    # URL at resolution time (app/proxy.py), never persisted here.
    # The CHECK backstops the EXPLICIT⇒URL invariant at the schema level: EXPLICIT
    # with an empty URL silently falls back to direct egress (proxy bypass), and
    # app-level validation alone is one forgotten writer away from that state —
    # update_settings enforces it under a row lock, the constraint catches the rest.
    __table_args__ = (
        CheckConstraint("mode != 'EXPLICIT' OR proxy_url != ''", name="ck_proxysettings_explicit_requires_url"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    mode: str = "SYSTEM"  # "NONE" | "SYSTEM" | "EXPLICIT" (app/proxy.py ProxyMode)
    proxy_url: str = ""
    no_proxy: str = ""
    updated_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))


class OIDCSettings(SQLModel, table=True):
    # Singleton (id == 1): admin-editable SSO/OIDC configuration (#32), seeded from
    # the ICEBERG_EBS_AUTH_MODE / ICEBERG_EBS_OIDC_* env on first read
    # (app/oidc_settings.py). Holds NO secret — the per-provider client secrets are
    # env-only (settings.oidc_<provider>_client_secret) and never persisted here.
    id: Optional[int] = Field(default=None, primary_key=True)
    auth_mode: str = "both"  # local | oidc | both
    oidc_redirect_base_url: str = ""

    oidc_entra_enabled: bool = False
    oidc_entra_client_id: str = ""
    oidc_entra_tenant_id: str = ""
    oidc_entra_scopes: str = "openid email profile"
    oidc_entra_role_claim: str = ""
    oidc_entra_role_map: str = ""

    oidc_authentik_enabled: bool = False
    oidc_authentik_client_id: str = ""
    oidc_authentik_base_url: str = ""
    oidc_authentik_app_slug: str = ""
    oidc_authentik_scopes: str = "openid email profile"
    oidc_authentik_role_claim: str = "groups"
    oidc_authentik_role_map: str = ""

    oidc_auth0_enabled: bool = False
    oidc_auth0_client_id: str = ""
    oidc_auth0_domain: str = ""
    oidc_auth0_scopes: str = "openid email profile"
    oidc_auth0_role_claim: str = ""
    oidc_auth0_role_map: str = ""

    oidc_okta_enabled: bool = False
    oidc_okta_client_id: str = ""
    oidc_okta_domain: str = ""
    oidc_okta_auth_server: str = ""
    oidc_okta_scopes: str = "openid email profile"
    oidc_okta_role_claim: str = "groups"
    oidc_okta_role_map: str = ""

    updated_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))


class AlertLog(SQLModel, table=True):
    # History rows: severing FKs (SET NULL) keeps the audit trail when the rule /
    # destination / owning user is deleted; extension deletion removes its logs.
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_id: Optional[int] = Field(default=None, foreign_key="alertrule.id", ondelete="SET NULL", index=True)
    destination_id: Optional[int] = Field(default=None, foreign_key="alertdestination.id", ondelete="SET NULL")
    extension_id: int = Field(foreign_key="extension.id", ondelete="CASCADE", index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", ondelete="SET NULL", index=True)
    event_type: str
    detail: str  # JSON: {"old": ..., "new": ...}
    sent_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    success: bool
    error: Optional[str] = None
