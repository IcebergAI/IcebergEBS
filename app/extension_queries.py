"""Shared extension filter/sort/count query layer (#68, #163).

One home for the filtering, sorting and counting logic behind the extension
list API, the export endpoint and the dashboard, so the three call sites can't
drift. The API endpoints build :class:`ExtensionFilters` from typed Query
params (via the ``extension_filters`` dependency in ``app.routes.api``); the
dashboard builds it from coerced raw strings (tolerating junk from a browser).
"""

from dataclasses import dataclass

from sqlalchemy import func, or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension

# Exposure ("blast radius", #29) is risk × org footprint — derived, never stored.
# A SQL expression lets it be ORDER BY'd without a denormalised column; NULL when
# either factor is NULL, so the existing nullslast/nullsfirst handling applies.
EXPOSURE_EXPR = Extension.risk_score * Extension.install_footprint

# Risk band → score range [low, high) used to filter by risk level. Mirrors the
# thresholds in app.scoring.risk_level (75/50/25) — the single source of truth.
RISK_BANDS: dict[str, tuple[int, int | None]] = {
    "critical": (75, None),
    "high": (50, 75),
    "medium": (25, 50),
    "low": (0, 25),
}

SORT_COLUMNS = {
    "name": Extension.name,
    "risk_score": Extension.risk_score,
    "publisher": Extension.publisher,
    "install_count": Extension.install_count,
    "last_updated": Extension.last_updated,
    "added_at": Extension.added_at,
    "exposure": EXPOSURE_EXPR,
}


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so a literal % / _ in a search term isn't treated
    as a pattern (escape char is backslash, passed via escape="\\")."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def exposure(risk_score: int | None, install_footprint: int | None) -> int | None:
    """Exposure / "blast radius" = risk_score × org footprint (#29). None unless
    both factors are known. Mirrors the SQL ``EXPOSURE_EXPR`` used for sorting."""
    if risk_score is None or install_footprint is None:
        return None
    return risk_score * install_footprint


@dataclass(frozen=True)
class ExtensionFilters:
    """Shared filter/sort params for the extension list, export and dashboard.

    One definition so the three call sites can't drift. The API endpoints build it
    from typed Query params (FastAPI 422s on bad input via the ``extension_filters``
    dependency); the dashboard builds it from coerced raw strings (tolerating junk
    from a browser). ``build_extension_query`` consumes it. ``publisher`` is only
    used by the API endpoints — the dashboard leaves it None."""

    store: str | None = None
    risk: str | None = None
    publisher: str | None = None
    q: str | None = None
    sort: str = "risk_score"
    order: str = "desc"


def build_extension_query(user_id: int, filters: ExtensionFilters):
    """Build the filtered + sorted ``select(Extension)`` shared by the list API,
    the export endpoint and the dashboard. No limit/offset — the caller paginates.
    Unknown sort columns fall back to risk_score; an ``id`` tie-breaker keeps
    pagination stable across pages."""
    stmt = select(Extension).where(Extension.user_id == user_id)
    if filters.store:
        stmt = stmt.where(Extension.store == filters.store)
    if filters.risk and filters.risk in RISK_BANDS:
        low, high = RISK_BANDS[filters.risk]
        stmt = stmt.where(Extension.risk_score.is_not(None), Extension.risk_score >= low)
        if high is not None:
            stmt = stmt.where(Extension.risk_score < high)
    if filters.publisher:
        stmt = stmt.where(Extension.publisher == filters.publisher)
    if filters.q:
        like = f"%{_escape_like(filters.q)}%"
        stmt = stmt.where(
            or_(
                Extension.name.ilike(like, escape="\\"),
                Extension.publisher.ilike(like, escape="\\"),
                Extension.extension_id.ilike(like, escape="\\"),
            )
        )
    col = SORT_COLUMNS.get(filters.sort, Extension.risk_score)
    primary = col.desc().nullslast() if filters.order == "desc" else col.asc().nullsfirst()
    return stmt.order_by(primary, Extension.id.asc())


async def count_rows(session: AsyncSession, stmt) -> int:
    """Total rows matching a built query, ignoring its ORDER BY / pagination."""
    return await session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
