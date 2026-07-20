from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import CheckConstraint, Column, DateTime, Index, desc, text
from sqlmodel import Field, SQLModel, UniqueConstraint

from app.utils import host_permissions_of, json_list, json_object


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
    # SSO identity (#32): an OIDC account is keyed on the immutable, validated
    # (oidc_issuer, oidc_subject) pair — never the mutable email claim, and never
    # the admin-configurable adapter key (which could be re-pointed at a different
    # issuer, letting a colliding `sub` inherit an account). A `sub` is unique only
    # within its issuer (OIDC spec). Postgres treats NULL values as distinct, so
    # local rows (issuer/subject both NULL) never collide with each other. This pair
    # is globally unique; `provision_oidc_user` additionally scopes its MATCH to
    # `auth_provider` so a hostile provider that spoofs another's issuer can't inherit
    # its account (#226) — this constraint is that rule's DB backstop.
    __table_args__ = (
        UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_user_issuer_subject"),
        # SSO accounts must not share a (already-lowercased) email: JIT provisioning
        # denies email collisions, but two concurrent first-time callbacks with
        # different subjects could otherwise both pass the app-level check and create
        # duplicate rows for the same address — this closes that race at the DB layer
        # (the #217 "strongest enforcement" rule). Partial so local accounts, whose
        # emails are free-form and may repeat/be NULL, are unaffected.
        Index(
            "uq_user_sso_email",
            "email",
            unique=True,
            postgresql_where=text("oidc_subject IS NOT NULL"),
        ),
        # Schema backstop for the identity invariant the provisioning code relies on
        # (the #217 pattern): a row is EITHER local (issuer+subject NULL) OR SSO
        # (both set). A "local" row carrying a subject, or an SSO row missing its
        # issuer, is unresolvable by the (issuer, subject) match — make the ambiguous
        # states unrepresentable, not just avoided.
        CheckConstraint(
            "(auth_provider = 'local') = (oidc_subject IS NULL)",
            name="ck_user_local_xor_subject",
        ),
        CheckConstraint(
            "(oidc_issuer IS NULL) = (oidc_subject IS NULL)",
            name="ck_user_issuer_subject_together",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    # NULL for SSO-provisioned accounts: they have no local password and are
    # refused by the password login path (see auth.verify_credentials).
    password_hash: Optional[str] = None
    email: Optional[str] = None
    is_admin: bool = False
    # "local" for password accounts, else the OIDC adapter key (#32) — used to pick
    # the adapter + for the admin-UI badge, NOT as the identity key (see __table_args__).
    auth_provider: str = Field(default="local", index=True)
    # The validated token issuer (`iss`); with oidc_subject it is the account key.
    oidc_issuer: Optional[str] = None
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

    def host_permissions_list(self) -> list[str]:
        """Stored host permissions (from package_analysis) as a list of strings; [] when the
        analysis is missing/malformed, the ``host_permissions`` value is not a list, or its
        members aren't strings. The single guard for this field (``utils.host_permissions_of``)
        — the scorer (``set(host_permissions)``), the notifications diff, the JSON DTO and the
        detail page all read it, and a stored string would otherwise iterate char-by-char into
        a silently wrong score / per-character perm tags, or a non-iterable would 500 (#291)."""
        return host_permissions_of(self.analysis_dict())

    def risk_detail_dict(self) -> dict | None:
        """Stored risk_detail breakdown as a dict, or None when absent/malformed/not an object."""
        return json_object(self.risk_detail, "risk_detail", self.id)

    # The pending_alert_events marker is decoded by services._parse_pending_events, which
    # returns typed ChangeEvents (defined in notifications.py, so it can't live here without
    # a circular import) and drops non-dict *and* malformed-event entries in one place (#197).


class FetchLog(SQLModel, table=True):
    # Composite index for the dashboard's latest-log-per-extension lookup (#284):
    # the correlated LATERAL … ORDER BY (extension_id, fetched_at DESC, id DESC)
    # LIMIT 1 in routes/ui.py:_latest_fetch_logs fetches one row per extension over
    # this index on every dashboard render; without it the single-column extension_id
    # index degrades to a sort of the whole per-extension history — the same shape
    # sibling InstallCountHistory already indexes.
    __table_args__ = (
        Index(
            "ix_fetchlog_extension_fetched_id",
            "extension_id",
            desc("fetched_at"),
            desc("id"),
        ),
    )

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
    # Two CHECKs backstop the routing invariants at the schema level, because
    # app-level validation is one forgotten writer (raw SQL, a migration backfill,
    # a direct update_settings call) away from a silent fail-open to direct egress:
    #  - mode is constrained to the exact ProxyMode enum (case-sensitive), so a junk
    #    or lowercase value ('explicit') can't be persisted — the resolver would read
    #    an unknown mode as SYSTEM and an EXPLICIT-with-no-URL as direct (#230). This
    #    mirrors the OIDCSettings.auth_mode CHECK added for the same reason (#218).
    #  - EXPLICIT requires a non-empty proxy_url (EXPLICIT with an empty URL silently
    #    falls back to direct egress / proxy bypass).
    # update_settings enforces both under a row lock; the constraints catch the rest.
    __table_args__ = (
        CheckConstraint("mode IN ('NONE', 'SYSTEM', 'EXPLICIT')", name="ck_proxysettings_mode"),
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
    # Schema backstops for the invariants oidc_settings.update_settings enforces
    # under a row lock (the #217 pattern): a writer that bypasses the helper — a
    # migration backfill, manual SQL, a future code path — can't persist a junk
    # auth_mode or an oidc-only config with no enabled provider, either of which
    # would make the fail-closed startup validation abort boot with no repair path.
    __table_args__ = (
        CheckConstraint("auth_mode IN ('local', 'oidc', 'both')", name="ck_oidcsettings_auth_mode"),
        CheckConstraint(
            "auth_mode <> 'oidc' OR (oidc_entra_enabled OR oidc_authentik_enabled "
            "OR oidc_auth0_enabled OR oidc_okta_enabled)",
            name="ck_oidcsettings_oidc_requires_provider",
        ),
    )

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
