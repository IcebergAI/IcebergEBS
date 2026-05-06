from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel, UniqueConstraint

_utcnow = lambda: datetime.now(timezone.utc)


class Extension(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("store", "extension_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
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
    extension_id: int = Field(foreign_key="extension.id")
    fetched_at: datetime = Field(default_factory=_utcnow)
    success: bool
    error_message: Optional[str] = None
    risk_score_before: Optional[int] = None
    risk_score_after: Optional[int] = None


class InstallCountHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    extension_id: int = Field(foreign_key="extension.id")
    recorded_at: datetime = Field(default_factory=_utcnow)
    install_count: int
