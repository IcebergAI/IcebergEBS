from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel, UniqueConstraint

_utcnow = lambda: datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    email: Optional[str] = None
    is_admin: bool = False
    created_at: datetime = Field(default_factory=_utcnow)


class Extension(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("user_id", "store", "extension_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", index=True)
    store: str  # "chrome" | "vscode" | "edge"
    extension_id: str
    name: str
    publisher: str
    description: Optional[str] = None
    version: str
    install_count: Optional[int] = None
    last_updated: Optional[datetime] = None
    permissions: str = "[]"  # JSON-encoded list
    store_url: str
    added_at: datetime = Field(default_factory=_utcnow)
    last_fetched_at: Optional[datetime] = None
    watchlist: bool = True
    risk_score: Optional[int] = None
    risk_detail: Optional[str] = None  # JSON breakdown per signal
    package_analysis: Optional[str] = None  # JSON output from inspector


class FetchLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id", index=True)
    fetched_at: datetime = Field(default_factory=_utcnow)
    success: bool
    error_message: Optional[str] = None
    risk_score_before: Optional[int] = None
    risk_score_after: Optional[int] = None


class InstallCountHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id", index=True)
    recorded_at: datetime = Field(default_factory=_utcnow)
    install_count: int


class AlertDestination(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    label: str
    target: str  # webhook URL
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)


class AlertRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    destination_id: int = Field(foreign_key="alertdestination.id", index=True)
    extension_id: Optional[int] = Field(default=None, foreign_key="extension.id")
    event_type: str  # "risk_level_change" | "publisher_change" | "permission_change" | "new_version"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)


class ApiKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    label: str
    key_hash: str = Field(index=True)  # SHA-256 hex of raw key
    readonly: bool = False
    created_at: datetime = Field(default_factory=_utcnow)
    last_used_at: Optional[datetime] = None


class AlertLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_id: Optional[int] = Field(default=None, foreign_key="alertrule.id", index=True)
    destination_id: Optional[int] = Field(default=None, foreign_key="alertdestination.id")
    extension_id: int = Field(foreign_key="extension.id", index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", index=True)
    event_type: str
    detail: str  # JSON: {"old": ..., "new": ...}
    sent_at: datetime = Field(default_factory=_utcnow)
    success: bool
    error: Optional[str] = None
