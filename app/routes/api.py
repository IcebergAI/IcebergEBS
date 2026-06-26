import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete, func, or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_api_auth
from app.database import engine, get_session
from app.fetchers.base import FetchError
from app.models import AlertLog, AlertRule, Extension, FetchLog, InstallCountHistory, User
from app.scoring import risk_level
from app.services import fetch_and_store, fire_pending_alerts
from app.threat_intel import build_threat_intel_indicators

logger = logging.getLogger(__name__)

router = APIRouter()

StoreType = Literal["chrome", "vscode", "edge"]
RiskLevel = Literal["low", "medium", "high", "critical"]
SortField = Literal["name", "risk_score", "publisher", "install_count", "last_updated", "added_at"]
SortOrder = Literal["asc", "desc"]

# Risk band → score range [low, high) used to filter by risk level. Mirrors the
# thresholds in app.scoring.risk_level (75/50/25) — the single source of truth.
_RISK_BANDS: dict[str, tuple[int, int | None]] = {
    "critical": (75, None),
    "high": (50, 75),
    "medium": (25, 50),
    "low": (0, 25),
}

_SORT_COLUMNS = {
    "name": Extension.name,
    "risk_score": Extension.risk_score,
    "publisher": Extension.publisher,
    "install_count": Extension.install_count,
    "last_updated": Extension.last_updated,
    "added_at": Extension.added_at,
}

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so a literal % / _ in a search term isn't treated
    as a pattern (escape char is backslash, passed via escape="\\")."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_extension_query(
    user_id: int,
    *,
    store: str | None = None,
    risk: str | None = None,
    publisher: str | None = None,
    q: str | None = None,
    sort: str = "risk_score",
    order: str = "desc",
):
    """Build the filtered + sorted ``select(Extension)`` shared by the list API,
    the export endpoint and the dashboard. No limit/offset — the caller paginates.
    Unknown sort columns fall back to risk_score; an ``id`` tie-breaker keeps
    pagination stable across pages."""
    stmt = select(Extension).where(Extension.user_id == user_id)
    if store:
        stmt = stmt.where(Extension.store == store)
    if risk and risk in _RISK_BANDS:
        low, high = _RISK_BANDS[risk]
        stmt = stmt.where(Extension.risk_score.is_not(None), Extension.risk_score >= low)
        if high is not None:
            stmt = stmt.where(Extension.risk_score < high)
    if publisher:
        stmt = stmt.where(Extension.publisher == publisher)
    if q:
        like = f"%{_escape_like(q)}%"
        stmt = stmt.where(or_(
            Extension.name.ilike(like, escape="\\"),
            Extension.publisher.ilike(like, escape="\\"),
            Extension.extension_id.ilike(like, escape="\\"),
        ))
    col = _SORT_COLUMNS.get(sort, Extension.risk_score)
    primary = col.desc().nullslast() if order == "desc" else col.asc().nullsfirst()
    return stmt.order_by(primary, Extension.id.asc())


async def _count(session: AsyncSession, stmt) -> int:
    """Total rows matching a built query, ignoring its ORDER BY / pagination."""
    return await session.scalar(
        select(func.count()).select_from(stmt.order_by(None).subquery())
    ) or 0


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ExtensionIn(BaseModel):
    store: StoreType
    extension_id: str  # raw ID or full store URL


class PackageFindingOut(BaseModel):
    code: str
    severity: str
    title: str
    detail: str
    source: str
    file: str | None = None
    line: int | None = None


class ThreatIntelLookupOut(BaseModel):
    label: str
    url: str
    requires_copy: bool = False


class ThreatIntelIndicatorOut(BaseModel):
    type: str
    section: str = "primary"
    label: str
    value: str
    source: str
    description: str | None = None
    lookups: list[ThreatIntelLookupOut]


def _safe_json(raw: str | None, default: str, field: str, ext_id: int | None):
    """json.loads with a fallback: malformed stored JSON logs a warning instead of
    raising and 500-ing the endpoint (#17)."""
    try:
        return json.loads(raw or default)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Malformed %s JSON for extension %s — using fallback", field, ext_id)
        return json.loads(default)


class ExtensionOut(BaseModel):
    id: int
    store: str
    extension_id: str
    name: str
    publisher: str
    description: str | None
    version: str
    install_count: int | None
    last_updated: datetime | None
    permissions: list[str]
    host_permissions: list[str]
    store_url: str
    added_at: datetime
    last_fetched_at: datetime | None
    watchlist: bool
    risk_score: int | None
    risk_detail: dict | None
    risk_level: str | None
    findings: list[PackageFindingOut]
    threat_intel_indicators: list[ThreatIntelIndicatorOut]

    @classmethod
    def from_db(cls, ext: Extension, *, include_threat_intel: bool = True) -> "ExtensionOut":
        """Serialize an Extension.

        ``include_threat_intel=False`` skips building VirusTotal/OTX indicators —
        an O(domains × URLs) cost the list view never renders. The list endpoint
        opts out; single-extension views keep the default (D2 / #12).
        """
        # Parse defensively: a partial write or manual DB edit could leave invalid
        # JSON, which must not 500 the endpoint — fall back and log instead (#17).
        perms = _safe_json(ext.permissions, "[]", "permissions", ext.id)
        analysis_raw = _safe_json(ext.package_analysis, "null", "package_analysis", ext.id)
        host_perms = analysis_raw.get("host_permissions", []) if analysis_raw else []
        findings = analysis_raw.get("findings", []) if analysis_raw else []
        threat_intel_indicators = (
            build_threat_intel_indicators(analysis_raw) if include_threat_intel else []
        )
        detail = _safe_json(ext.risk_detail, "null", "risk_detail", ext.id)
        return cls(
            id=ext.id,
            store=ext.store,
            extension_id=ext.extension_id,
            name=ext.name,
            publisher=ext.publisher,
            description=ext.description,
            version=ext.version,
            install_count=ext.install_count,
            last_updated=ext.last_updated,
            permissions=perms,
            host_permissions=host_perms,
            store_url=ext.store_url,
            added_at=ext.added_at,
            last_fetched_at=ext.last_fetched_at,
            watchlist=ext.watchlist,
            risk_score=ext.risk_score,
            risk_detail=detail,
            risk_level=risk_level(ext.risk_score),
            findings=[PackageFindingOut(**finding) for finding in findings],
            threat_intel_indicators=[
                ThreatIntelIndicatorOut(**indicator)
                for indicator in threat_intel_indicators
            ],
        )


class PaginatedExtensions(BaseModel):
    items: list[ExtensionOut]
    total: int
    limit: int
    offset: int


class BulkItem(BaseModel):
    store: StoreType
    extension_id: str


class BulkIn(BaseModel):
    # Structured entries and/or a pasted CSV/newline blob ("store,extension_id"
    # per line, or a bare store URL whose store is auto-detected). At least one
    # source must be provided.
    items: list[BulkItem] | None = None
    text: str | None = None


class BulkResultItem(BaseModel):
    store: str | None
    extension_id: str | None
    status: str  # added | duplicate | invalid | error
    id: int | None = None
    detail: str | None = None


class BulkResult(BaseModel):
    added: int
    duplicates: int
    invalid: int
    errors: int
    results: list[BulkResultItem]


class WatchlistPatch(BaseModel):
    watchlist: bool


class HistoryPoint(BaseModel):
    recorded_at: datetime
    install_count: int


# ---------------------------------------------------------------------------
# Extension ID validation
# ---------------------------------------------------------------------------

_CHROME_EDGE_ID_RE = re.compile(r'^[a-p]{32}$')
_VSCODE_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$')


def _validate_extension_id(store: StoreType, extension_id: str) -> None:
    if store in ("chrome", "edge"):
        if not _CHROME_EDGE_ID_RE.match(extension_id):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid {store} extension ID — expected 32 characters a–p",
            )
    elif store == "vscode":
        if not _VSCODE_ID_RE.match(extension_id):
            raise HTTPException(
                status_code=422,
                detail="Invalid VS Code extension ID — expected publisher.name format",
            )


# ---------------------------------------------------------------------------
# URL normalisation helpers
# ---------------------------------------------------------------------------

def normalise_extension_id(store: StoreType, raw: str) -> str:
    """Extract the store-native ID from a full URL or return raw as-is."""
    raw = raw.strip()
    if not raw.startswith("http"):
        return raw

    parsed = urlparse(raw)
    if store == "chrome":
        # https://chromewebstore.google.com/detail/{name}/{id}
        parts = [p for p in parsed.path.split("/") if p]
        if parts and len(parts[-1]) == 32:
            return parts[-1]
        if len(parts) >= 2:
            return parts[-1]
    elif store == "vscode":
        # https://marketplace.visualstudio.com/items?itemName=publisher.name
        qs = parse_qs(parsed.query)
        if "itemName" in qs:
            return qs["itemName"][0]
    elif store == "edge":
        # https://microsoftedge.microsoft.com/addons/detail/{name}/{id}
        parts = [p for p in parsed.path.split("/") if p]
        if parts:
            return parts[-1]
    return raw


def _detect_store(value: str) -> StoreType | None:
    """Best-effort store detection from a store URL (mirrors the add-page JS)."""
    v = value.lower()
    if "chromewebstore.google.com" in v or "chrome.google.com/webstore" in v:
        return "chrome"
    if "marketplace.visualstudio.com" in v:
        return "vscode"
    if "microsoftedge.microsoft.com" in v:
        return "edge"
    return None


def _parse_bulk_text(text: str) -> list[dict]:
    """Parse a pasted CSV/newline blob into ``{store, extension_id}`` entries.

    Each non-empty, non-comment line is one of:
      - ``store,extension_id`` (or ``store extension_id``)
      - a bare store URL (store auto-detected, id extracted downstream)
    A line whose store can't be resolved is returned as an ``invalid`` result."""
    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Split into a leading token and the remainder on comma or whitespace.
        if "," in line:
            head, _, rest = line.partition(",")
        else:
            head, _, rest = line.partition(" ")
        head, rest = head.strip(), rest.strip()
        if head.lower() in ("chrome", "vscode", "edge") and rest:
            entries.append({"store": head.lower(), "extension_id": rest})
        elif (detected := _detect_store(line)) is not None:
            entries.append({"store": detected, "extension_id": line})
        else:
            entries.append({
                "store": None, "extension_id": line, "status": "invalid",
                "detail": "Could not determine store — use 'store,id' or a store URL",
            })
    return entries


# ---------------------------------------------------------------------------
# Core fetch-and-score helper (used by add + refresh)
# ---------------------------------------------------------------------------

async def _fetch_and_score(
    ext: Extension,
    session: AsyncSession,
    client: httpx.AsyncClient,
) -> Extension:
    score_before = ext.risk_score
    try:
        ext, events = await fetch_and_store(ext, session, client)
    except FetchError as exc:
        logger.warning("Fetch failed for extension %d: %s", ext.id, exc)
        session.add(FetchLog(
            extension_id=ext.id,
            success=False,
            error_message=str(exc),
            risk_score_before=score_before,
        ))
        await session.commit()
        raise HTTPException(status_code=502, detail="Failed to fetch extension from store")
    await session.commit()
    await session.refresh(ext)
    # Fire alerts only after the commit above releases the write lock, so
    # fire_alerts' own session can write the AlertLog without deadlocking SQLite.
    await fire_pending_alerts(events, ext, engine, client)
    return ext


async def _enroll_extension(
    store: str,
    raw_id: str,
    session: AsyncSession,
    client: httpx.AsyncClient,
    user_id: int,
) -> dict:
    """Validate, dedupe, then create + fetch-and-score one extension.

    The single enrollment primitive behind both the add and bulk endpoints.
    Returns a result dict with ``status`` in {added, duplicate, invalid, error}.
    On a failed first fetch it discards the placeholder row (and any failure
    FetchLog) so the user isn't left with an unanalysed extension."""
    extension_id = normalise_extension_id(store, raw_id)
    try:
        _validate_extension_id(store, extension_id)
    except HTTPException as exc:
        return {"store": store, "extension_id": extension_id, "status": "invalid", "detail": exc.detail}

    existing = (await session.exec(
        select(Extension).where(
            Extension.user_id == user_id,
            Extension.store == store,
            Extension.extension_id == extension_id,
        )
    )).first()
    if existing:
        return {"store": store, "extension_id": extension_id, "status": "duplicate", "id": existing.id}

    ext = Extension(
        user_id=user_id, store=store, extension_id=extension_id,
        name=extension_id, publisher="", version="", store_url="",
    )
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    ext_id = ext.id

    try:
        scored = await _fetch_and_score(ext, session, client)
    except HTTPException as exc:
        for fl in (await session.exec(
            select(FetchLog).where(FetchLog.extension_id == ext_id)
        )).all():
            await session.delete(fl)
        orphan = await session.get(Extension, ext_id)
        if orphan is not None:
            await session.delete(orphan)
        await session.commit()
        return {"store": store, "extension_id": extension_id, "status": "error", "detail": exc.detail}

    return {"store": store, "extension_id": extension_id, "status": "added", "id": scored.id}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/extensions", response_model=PaginatedExtensions)
async def list_extensions(
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
    store: StoreType | None = None,
    risk: RiskLevel | None = None,
    publisher: str | None = None,
    q: str | None = Query(None, description="Free-text search over name, publisher and id"),
    sort: SortField = "risk_score",
    order: SortOrder = "desc",
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
):
    stmt = build_extension_query(
        current_user.id, store=store, risk=risk, publisher=publisher, q=q, sort=sort, order=order,
    )
    total = await _count(session, stmt)
    rows = (await session.exec(stmt.limit(limit).offset(offset))).all()
    # Skip per-extension threat-intel indicator construction here — the list view
    # doesn't render it, and building it for every row is O(extensions × domains).
    return PaginatedExtensions(
        items=[ExtensionOut.from_db(r, include_threat_intel=False) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


# Flat "key fields" projection for export — score + identity + the headline risk
# signals, but not the heavy nested findings / threat-intel (those belong to the
# single-extension view). Order defines the CSV column order.
EXPORT_FIELDS = [
    "id", "store", "extension_id", "name", "publisher", "version",
    "install_count", "last_updated", "risk_score", "risk_level",
    "permissions", "watchlist", "added_at", "last_fetched_at",
]


def _export_row(ext: Extension) -> dict:
    perms = _safe_json(ext.permissions, "[]", "permissions", ext.id)
    return {
        "id": ext.id,
        "store": ext.store,
        "extension_id": ext.extension_id,
        "name": ext.name,
        "publisher": ext.publisher,
        "version": ext.version,
        "install_count": ext.install_count,
        "last_updated": ext.last_updated.isoformat() if ext.last_updated else None,
        "risk_score": ext.risk_score,
        "risk_level": risk_level(ext.risk_score),
        "permissions": ";".join(perms) if isinstance(perms, list) else "",
        "watchlist": ext.watchlist,
        "added_at": ext.added_at.isoformat() if ext.added_at else None,
        "last_fetched_at": ext.last_fetched_at.isoformat() if ext.last_fetched_at else None,
    }


@router.get("/extensions/export")
async def export_extensions(
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
    format: Literal["csv", "json"] = "csv",
    store: StoreType | None = None,
    risk: RiskLevel | None = None,
    publisher: str | None = None,
    q: str | None = Query(None, description="Free-text search over name, publisher and id"),
    sort: SortField = "risk_score",
    order: SortOrder = "desc",
):
    """Export the full (filtered) extension set with score + key fields, for
    reporting / downstream ingest. Shares the list endpoint's filter/sort params
    (`build_extension_query`) but is **not** paginated — it returns every match."""
    stmt = build_extension_query(
        current_user.id, store=store, risk=risk, publisher=publisher, q=q, sort=sort, order=order,
    )
    rows = [_export_row(e) for e in (await session.exec(stmt)).all()]

    if format == "json":
        return JSONResponse(
            rows,
            headers={"Content-Disposition": 'attachment; filename="marvin-extensions.json"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="marvin-extensions.csv"'},
    )


@router.post("/extensions", response_model=ExtensionOut, status_code=201)
async def add_extension(
    body: ExtensionIn,
    request: Request,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    client: httpx.AsyncClient = request.app.state.http_client
    result = await _enroll_extension(
        body.store, body.extension_id, session, client, current_user.id
    )
    if result["status"] == "invalid":
        raise HTTPException(status_code=422, detail=result["detail"])
    if result["status"] == "duplicate":
        raise HTTPException(status_code=409, detail="Extension already tracked")
    if result["status"] == "error":
        raise HTTPException(status_code=502, detail="Failed to fetch extension from store")
    ext = await session.get(Extension, result["id"])
    return ExtensionOut.from_db(ext)


MAX_BULK_ITEMS = 100


@router.post("/extensions/bulk", response_model=BulkResult)
async def bulk_add_extensions(
    body: BulkIn,
    request: Request,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Enroll many extensions in one request, reusing the add+score path.

    Accepts structured ``items`` and/or a pasted ``text`` blob ("store,id" per
    line or store URLs). Each entry is validated, de-duplicated against the
    user's existing extensions, then fetched + scored; the response reports a
    per-entry status (added / duplicate / invalid / error) plus tallies."""
    entries: list[dict] = []
    if body.items:
        entries.extend({"store": i.store, "extension_id": i.extension_id} for i in body.items)
    if body.text:
        entries.extend(_parse_bulk_text(body.text))

    if not entries:
        raise HTTPException(status_code=422, detail="No extensions provided")
    if len(entries) > MAX_BULK_ITEMS:
        raise HTTPException(
            status_code=422,
            detail=f"Too many extensions in one request (max {MAX_BULK_ITEMS})",
        )

    # Capture the id up front: each _enroll_extension commits, which expires the
    # current_user ORM attributes — re-reading current_user.id mid-loop would
    # trigger a lazy (sync) refresh outside the async context.
    user_id = current_user.id
    client: httpx.AsyncClient = request.app.state.http_client
    results: list[dict] = []
    for entry in entries:
        # Lines the parser already flagged as unresolvable pass straight through.
        if entry.get("status") == "invalid":
            results.append(entry)
            continue
        results.append(await _enroll_extension(
            entry["store"], entry["extension_id"], session, client, user_id
        ))

    tally = {"added": 0, "duplicate": 0, "invalid": 0, "error": 0}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    return BulkResult(
        added=tally["added"],
        duplicates=tally["duplicate"],
        invalid=tally["invalid"],
        errors=tally["error"],
        results=[BulkResultItem(**r) for r in results],
    )


@router.get("/extensions/{ext_id}", response_model=ExtensionOut)
async def get_extension(
    ext_id: int,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    return ExtensionOut.from_db(ext)


@router.delete("/extensions/{ext_id}")
async def delete_extension(
    ext_id: int,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")

    # Remove all child rows referencing this extension in FK-safe order.
    # AlertLog references both the extension and (optionally) a rule, so it goes first.
    await session.execute(sa_delete(AlertLog).where(AlertLog.extension_id == ext_id))
    await session.execute(sa_delete(AlertRule).where(AlertRule.extension_id == ext_id))
    await session.execute(sa_delete(FetchLog).where(FetchLog.extension_id == ext_id))
    await session.execute(sa_delete(InstallCountHistory).where(InstallCountHistory.extension_id == ext_id))

    await session.delete(ext)
    await session.commit()
    return {"ok": True}


@router.post("/extensions/{ext_id}/refresh", response_model=ExtensionOut)
async def refresh_extension(
    ext_id: int,
    request: Request,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    client: httpx.AsyncClient = request.app.state.http_client
    return ExtensionOut.from_db(await _fetch_and_score(ext, session, client))


@router.patch("/extensions/{ext_id}/watchlist", response_model=ExtensionOut)
async def toggle_watchlist(
    ext_id: int,
    body: WatchlistPatch,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    ext.watchlist = body.watchlist
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ExtensionOut.from_db(ext)


@router.get("/extensions/{ext_id}/history", response_model=list[HistoryPoint])
async def get_history(
    ext_id: int,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    rows = (await session.exec(
        select(InstallCountHistory)
        .where(InstallCountHistory.extension_id == ext_id)
        .order_by(InstallCountHistory.recorded_at)
    )).all()
    return [HistoryPoint(recorded_at=r.recorded_at, install_count=r.install_count) for r in rows]
