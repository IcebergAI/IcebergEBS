from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel, UniqueConstraint


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
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    email: Optional[str] = None
    is_admin: bool = False
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_tz_column(nullable=False))
    # Bumped on password change; sessions/cookies signed before this instant are
    # rejected, invalidating other-device sessions on reset (M1 / #6).
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
