import csv
import io
import logging
import re
from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, StringConstraints
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import engine
from app.deps import CurrentUser, SessionDep, get_owned_or_404
from app.extension_queries import ExtensionFilters, build_extension_query, count_rows, exposure
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog, InstallCountHistory, InstallObservation
from app.scoring import risk_level
from app.services import fetch_and_store, fire_pending_alerts
from app.threat_intel import build_threat_intel_indicators

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["extensions"])

StoreType = Literal["chrome", "vscode", "edge"]
RiskLevel = Literal["low", "medium", "high", "critical"]
SortField = Literal["name", "risk_score", "publisher", "install_count", "last_updated", "added_at", "exposure"]
SortOrder = Literal["asc", "desc"]

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


def extension_filters(
    store: StoreType | None = None,
    risk: RiskLevel | None = None,
    publisher: str | None = None,
    q: Annotated[str | None, Query(description="Free-text search over name, publisher and id")] = None,
    sort: SortField = "risk_score",
    order: SortOrder = "desc",
) -> ExtensionFilters:
    """FastAPI dependency: validate + collect the filter/sort query params shared by
    the list and export endpoints (declared once here instead of on each route)."""
    return ExtensionFilters(store=store, risk=risk, publisher=publisher, q=q, sort=sort, order=order)


FilterParams = Annotated[ExtensionFilters, Depends(extension_filters)]


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

    @classmethod
    def from_raw(cls, finding: object) -> "PackageFindingOut | None":
        """Build from one stored finding, tolerating the malformed shapes a partial write
        or manual DB edit can leave (#150): a non-dict entry is skipped (returns None), and
        missing/blank string fields fall back to the same defaults the detail page uses
        (`findings_view`), so one bad finding can't 500 the whole `ExtensionOut` response the
        way a bare `PackageFindingOut(**finding)` would."""
        if not isinstance(finding, dict):
            return None
        code = str(finding.get("code") or "")
        line = finding.get("line")
        return cls(
            code=code,
            severity=str(finding.get("severity") or "low"),
            title=str(finding.get("title") or code or "Detection finding"),
            detail=str(finding.get("detail") or ""),
            source=str(finding.get("source") or "package"),
            file=str(finding["file"]) if isinstance(finding.get("file"), str) else None,
            line=line if isinstance(line, int) and not isinstance(line, bool) else None,
        )


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
    install_footprint: int | None
    exposure: int | None  # risk_score × install_footprint, or None if either is unset
    findings: list[PackageFindingOut]
    threat_intel_indicators: list[ThreatIntelIndicatorOut]

    @classmethod
    def from_db(cls, ext: Extension, *, include_threat_intel: bool = True) -> "ExtensionOut":
        """Serialize an Extension.

        ``include_threat_intel=False`` skips building VirusTotal/OTX indicators —
        an O(domains × URLs) cost the list view never renders. The list endpoint
        opts out; single-extension views keep the default (D2 / #12).
        """
        # The Extension accessors own the defensive parse — a partial write or manual DB
        # edit can't 500 the endpoint (#17/#61), they log + fall back instead (#167).
        perms = ext.permissions_list()
        analysis_raw = ext.analysis_dict()
        host_perms_raw = analysis_raw.get("host_permissions", []) if analysis_raw else []
        # A wrong-shaped stored value must not 500 the list[str] DTO: drop a non-list
        # container and any non-string members (partial write / manual edit, #150).
        host_perms = [h for h in host_perms_raw if isinstance(h, str)] if isinstance(host_perms_raw, list) else []
        findings_raw = analysis_raw.get("findings", []) if analysis_raw else []
        # Tolerate malformed findings (non-dict entries, dicts missing required fields, or a
        # non-list `findings`) the way the detail page already does, instead of letting
        # PackageFindingOut(**finding) raise a 500 on the same threat model (#150).
        findings = (
            [f for f in (PackageFindingOut.from_raw(x) for x in findings_raw) if f is not None]
            if isinstance(findings_raw, list)
            else []
        )
        threat_intel_indicators = build_threat_intel_indicators(analysis_raw) if include_threat_intel else []
        detail = ext.risk_detail_dict()
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
            install_footprint=ext.install_footprint,
            exposure=exposure(ext.risk_score, ext.install_footprint),
            findings=findings,
            threat_intel_indicators=[ThreatIntelIndicatorOut(**indicator) for indicator in threat_intel_indicators],
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


class InventoryItem(BaseModel):
    # One SOAR-reported install: which extension, on which asset, plus optional
    # asset metadata. ``extension_id`` may be a raw id or a store URL (normalised
    # downstream, like the add/bulk endpoints).
    store: StoreType
    extension_id: str
    # Stripped + bounded; a blank asset_id is rejected per-item in the loop (#154) rather than
    # 422-ing the whole SOAR batch. Left empty, it would upsert a real InstallObservation and
    # count as a distinct asset — inflating install_footprint and therefore exposure.
    asset_id: Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)]
    asset_type: str | None = None
    department: str | None = None
    source: str | None = None  # overrides the batch-level source for this row


class InventoryBatch(BaseModel):
    source: str | None = None  # batch-level default feed name (e.g. "crowdstrike")
    observations: list[InventoryItem]


class InventoryResultItem(BaseModel):
    store: str | None
    extension_id: str | None
    asset_id: str | None
    status: str  # deferred | observed | invalid | error
    id: int | None = None  # resolved extension id
    detail: str | None = None


class InventoryResult(BaseModel):
    observations: int  # observation rows written (deferred + observed)
    deferred: int  # extensions auto-enrolled by this batch, scoring deferred to the scheduler (#78)
    duplicates: int  # observations for already-tracked extensions
    invalid: int
    errors: int
    results: list[InventoryResultItem]


class WatchlistPatch(BaseModel):
    watchlist: bool


class HistoryPoint(BaseModel):
    recorded_at: datetime
    install_count: int


# ---------------------------------------------------------------------------
# Extension ID validation
# ---------------------------------------------------------------------------

_CHROME_EDGE_ID_RE = re.compile(r"^[a-p]{32}$")
_VSCODE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


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
            entries.append(
                {
                    "store": None,
                    "extension_id": line,
                    "status": "invalid",
                    "detail": "Could not determine store — use 'store,id' or a store URL",
                }
            )
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
    except (FetchError, httpx.TransportError) as exc:
        # A store/network failure: the fetcher raised FetchError, or a raw
        # httpx.TransportError propagated after RetryTransport exhausted its retries
        # (connect refused, timeout). Both mean the store is unreachable — the fetch is
        # the only step that raises these, before anything is staged, so no rollback is
        # needed. Match the scheduler's _refresh_one so the interactive path also records
        # a failure FetchLog (visible to the dashboard's fetch-health) and returns a 502
        # rather than a raw 500 (#148).
        logger.warning("Fetch failed for extension %d: %s", ext.id, exc)
        session.add(
            FetchLog(
                extension_id=ext.id,
                success=False,
                error_message=str(exc),
                risk_score_before=score_before,
            )
        )
        await session.commit()
        raise HTTPException(status_code=502, detail="Failed to fetch extension from store") from exc
    await session.commit()
    await session.refresh(ext)
    # Fire alerts only after committing above, so fire_alerts' own session can write
    # the AlertLog without contending with this request's open write transaction.
    await fire_pending_alerts(events, ext, engine, client)
    return ext


async def _find_extension(session: AsyncSession, user_id: int, store: str, extension_id: str) -> Extension | None:
    """Look up a user's extension by its (store, extension_id) identity."""
    return (
        await session.exec(
            select(Extension).where(
                Extension.user_id == user_id,
                Extension.store == store,
                Extension.extension_id == extension_id,
            )
        )
    ).first()


async def _enroll_extension(
    store: str,
    raw_id: str,
    session: AsyncSession,
    client: httpx.AsyncClient,
    user_id: int,
    *,
    score: bool = True,
) -> dict:
    """Validate, dedupe, then create one extension.

    The single enrollment primitive behind the add, bulk and inventory endpoints.
    Returns a result dict with ``status`` in {added, deferred, duplicate, invalid,
    error}. When ``score`` is True (add/bulk) the extension is fetched + scored
    inline, and a failed first fetch discards the placeholder row (so the user
    isn't left with an unanalysed extension). When ``score`` is False (inventory,
    #78) the placeholder is created but **not** fetched — it stays ``watchlist=True``
    and unscored, so the scheduler scores it on its next run; the status is
    ``deferred``. This keeps a large SOAR batch of unknown extensions from doing
    hundreds of sequential store fetches inside one request."""
    extension_id = normalise_extension_id(store, raw_id)
    try:
        _validate_extension_id(store, extension_id)
    except HTTPException as exc:
        return {"store": store, "extension_id": extension_id, "status": "invalid", "detail": exc.detail}

    existing = await _find_extension(session, user_id, store, extension_id)
    if existing:
        return {"store": store, "extension_id": extension_id, "status": "duplicate", "id": existing.id}

    ext = Extension(
        user_id=user_id,
        store=store,
        extension_id=extension_id,
        name=extension_id,
        publisher="",
        version="",
        store_url="",
    )
    session.add(ext)
    try:
        await session.commit()
    except IntegrityError:
        # A concurrent request inserted the same (user, store, extension_id) between
        # the dedupe SELECT above and this commit — the unique constraint fired.
        # Treat it as a duplicate instead of surfacing a 500 (#76).
        await session.rollback()
        existing = await _find_extension(session, user_id, store, extension_id)
        if existing:
            return {"store": store, "extension_id": extension_id, "status": "duplicate", "id": existing.id}
        raise
    await session.refresh(ext)
    ext_id = ext.id

    if not score:
        # Defer scoring to the scheduler (#78): the placeholder is watchlist=True and
        # unscored, so refresh_watchlist scores it on its next run. detect_changes
        # returns [] on that first fetch (last_fetched_at is None), so no alerts fire.
        return {"store": store, "extension_id": extension_id, "status": "deferred", "id": ext_id}

    try:
        scored = await _fetch_and_score(ext, session, client)
    except HTTPException as exc:
        await _discard_placeholder(session, ext_id)
        return {"store": store, "extension_id": extension_id, "status": "error", "detail": exc.detail}
    except Exception:
        # An unexpected failure (inspector bug, DB error, …) must not leave an
        # unscored placeholder on the watchlist — the exact state the FetchError
        # cleanup above prevents (#75). Roll back the poisoned transaction, drop
        # the orphan, then re-raise so a genuine bug still surfaces as a 500.
        await session.rollback()
        await _discard_placeholder(session, ext_id)
        raise

    return {"store": store, "extension_id": extension_id, "status": "added", "id": scored.id}


async def _discard_placeholder(session: AsyncSession, ext_id: int) -> None:
    """Delete a placeholder Extension and its FetchLog rows after a failed first
    fetch, committing the cleanup. Best-effort: a cleanup failure is swallowed so it
    can't mask the original error."""
    try:
        for fl in (await session.exec(select(FetchLog).where(FetchLog.extension_id == ext_id))).all():
            await session.delete(fl)
        orphan = await session.get(Extension, ext_id)
        if orphan is not None:
            await session.delete(orphan)
        await session.commit()
    except Exception:
        logger.exception("Failed to discard placeholder extension %d after a failed first fetch", ext_id)
        await session.rollback()


async def _upsert_observation(
    session: AsyncSession,
    extension_id: int,
    item: InventoryItem,
    default_source: str | None,
    now: datetime,
) -> None:
    """Insert or refresh one (extension, asset) install observation.

    Keyed on the schema's ``(extension_id, asset_id)`` unique pair: a re-push
    bumps ``last_seen`` and refreshes the asset metadata; a first sighting sets
    ``first_seen``. Caller commits and recomputes ``install_footprint``.

    Implemented as a single Postgres ``INSERT … ON CONFLICT DO UPDATE`` so
    concurrent/retried pushes of the same (extension, asset) can't race a
    select-then-insert into an IntegrityError 500 (#76)."""
    source = item.source or default_source or "soar"
    stmt = pg_insert(InstallObservation).values(
        extension_id=extension_id,
        asset_id=item.asset_id,
        asset_type=item.asset_type,
        department=item.department,
        source=source,
        first_seen=now,
        last_seen=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["extension_id", "asset_id"],
        set_={
            "last_seen": now,
            "asset_type": item.asset_type,
            "department": item.department,
            "source": source,
        },
    )
    await session.execute(stmt)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/extensions")
async def list_extensions(
    current_user: CurrentUser,
    session: SessionDep,
    filters: FilterParams,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedExtensions:
    stmt = build_extension_query(current_user.id, filters)
    total = await count_rows(session, stmt)
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
    "id",
    "store",
    "extension_id",
    "name",
    "publisher",
    "version",
    "install_count",
    "last_updated",
    "risk_score",
    "risk_level",
    "install_footprint",
    "exposure",
    "permissions",
    "watchlist",
    "added_at",
    "last_fetched_at",
]


# Leading characters a spreadsheet (Excel/LibreOffice/Sheets) treats as the start of a
# formula. Extension name/publisher are attacker-controlled (scraped from the store, and
# this tool exists to track *suspicious* extensions), and the analyst opens the export in
# Excel — so a cell like `=HYPERLINK(...)` or `=cmd|'/c ...'!A1` would execute on open.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Prefix a formula-triggering leading character with a single quote so the cell is
    treated as text, not a formula — the OWASP CSV-injection mitigation (#147). Applied on
    the CSV path only (JSON export is not opened as a spreadsheet); non-str cells pass
    through untouched."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _export_row(ext: Extension) -> dict:
    perms = ext.permissions_list()
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
        "install_footprint": ext.install_footprint,
        "exposure": exposure(ext.risk_score, ext.install_footprint),
        "permissions": ";".join(perms) if isinstance(perms, list) else "",
        "watchlist": ext.watchlist,
        "added_at": ext.added_at.isoformat() if ext.added_at else None,
        "last_fetched_at": ext.last_fetched_at.isoformat() if ext.last_fetched_at else None,
    }


@router.get("/extensions/export")
async def export_extensions(
    current_user: CurrentUser,
    session: SessionDep,
    filters: FilterParams,
    format: Literal["csv", "json"] = "csv",
):
    """Export the full (filtered) extension set with score + key fields, for
    reporting / downstream ingest. Shares the list endpoint's filter/sort params
    (`build_extension_query`) but is **not** paginated — it returns every match."""
    stmt = build_extension_query(current_user.id, filters)
    rows = [_export_row(e) for e in (await session.exec(stmt)).all()]

    if format == "json":
        return JSONResponse(
            rows,
            headers={"Content-Disposition": 'attachment; filename="icebergebs-extensions.json"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="icebergebs-extensions.csv"'},
    )


@router.post("/extensions", status_code=201)
async def add_extension(
    body: ExtensionIn,
    request: Request,
    current_user: CurrentUser,
    session: SessionDep,
) -> ExtensionOut:
    client: httpx.AsyncClient = request.app.state.http_client
    result = await _enroll_extension(body.store, body.extension_id, session, client, current_user.id)
    if result["status"] == "invalid":
        raise HTTPException(status_code=422, detail=result["detail"])
    if result["status"] == "duplicate":
        raise HTTPException(status_code=409, detail="Extension already tracked")
    if result["status"] == "error":
        raise HTTPException(status_code=502, detail="Failed to fetch extension from store")
    ext = await session.get(Extension, result["id"])
    return ExtensionOut.from_db(ext)


MAX_BULK_ITEMS = 100


@router.post("/extensions/bulk")
async def bulk_add_extensions(
    body: BulkIn,
    request: Request,
    current_user: CurrentUser,
    session: SessionDep,
) -> BulkResult:
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
        results.append(await _enroll_extension(entry["store"], entry["extension_id"], session, client, user_id))

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


MAX_INVENTORY_ITEMS = 1000


@router.post("/inventory")
async def ingest_inventory(
    body: InventoryBatch,
    request: Request,
    current_user: CurrentUser,
    session: SessionDep,
) -> InventoryResult:
    """Bulk-upsert org install inventory from the SOAR (#29).

    Each observation resolves its extension through the shared enrollment
    primitive with ``score=False`` — so an **unknown** extension is auto-enrolled
    onto the watchlist but its scoring is **deferred to the scheduler** (#78),
    keeping a large batch of unknown extensions from doing hundreds of sequential
    store fetches inside one request. Each row then upserts an `InstallObservation`
    keyed on (extension, asset). After the batch, each touched extension's cached
    `install_footprint` (distinct asset count) is recomputed; exposure
    (= risk_score × footprint) is derived on read once the scheduler has scored it."""
    if not body.observations:
        raise HTTPException(status_code=422, detail="No observations provided")
    if len(body.observations) > MAX_INVENTORY_ITEMS:
        raise HTTPException(
            status_code=422,
            detail=f"Too many observations in one request (max {MAX_INVENTORY_ITEMS})",
        )

    # Capture the id up front: each _enroll_extension commits, expiring the
    # current_user ORM attributes (same caveat as the bulk endpoint).
    user_id = current_user.id
    client: httpx.AsyncClient = request.app.state.http_client
    now = datetime.now(timezone.utc)

    results: list[dict] = []
    affected: set[int] = set()
    tally = {"deferred": 0, "observed": 0, "invalid": 0, "error": 0}
    for item in body.observations:
        if not item.asset_id:
            # A blank asset_id (empty or whitespace, now stripped) is not a real asset — reject
            # it so it never becomes an InstallObservation that inflates install_footprint (#154).
            tally["invalid"] += 1
            results.append(
                {
                    "store": item.store,
                    "extension_id": item.extension_id,
                    "asset_id": item.asset_id,
                    "status": "invalid",
                    "detail": "asset_id must not be empty",
                }
            )
            continue
        enroll = await _enroll_extension(item.store, item.extension_id, session, client, user_id, score=False)
        norm_id = enroll.get("extension_id", item.extension_id)
        if enroll["status"] in ("invalid", "error"):
            tally[enroll["status"]] += 1
            results.append(
                {
                    "store": item.store,
                    "extension_id": norm_id,
                    "asset_id": item.asset_id,
                    "status": enroll["status"],
                    "detail": enroll.get("detail"),
                }
            )
            continue
        ext_id = enroll["id"]
        await _upsert_observation(session, ext_id, item, body.source, now)
        affected.add(ext_id)
        # A freshly-created placeholder is "deferred" (scheduler will score it);
        # an already-tracked extension is "observed".
        status = "deferred" if enroll["status"] == "deferred" else "observed"
        tally[status] += 1
        results.append(
            {
                "store": item.store,
                "extension_id": norm_id,
                "asset_id": item.asset_id,
                "status": status,
                "id": ext_id,
            }
        )

    # Recompute the cached footprint (distinct assets) for every touched extension.
    for ext_id in affected:
        count = await session.scalar(
            select(func.count(func.distinct(InstallObservation.asset_id))).where(
                InstallObservation.extension_id == ext_id
            )
        )
        ext = await session.get(Extension, ext_id)
        if ext is not None:
            ext.install_footprint = int(count or 0)
            session.add(ext)
    await session.commit()

    return InventoryResult(
        observations=tally["deferred"] + tally["observed"],
        deferred=tally["deferred"],
        duplicates=tally["observed"],
        invalid=tally["invalid"],
        errors=tally["error"],
        results=[InventoryResultItem(**r) for r in results],
    )


@router.get("/extensions/{ext_id}")
async def get_extension(
    ext_id: int,
    current_user: CurrentUser,
    session: SessionDep,
) -> ExtensionOut:
    ext = await get_owned_or_404(session, Extension, ext_id, current_user.id)
    return ExtensionOut.from_db(ext)


@router.delete("/extensions/{ext_id}")
async def delete_extension(
    ext_id: int,
    current_user: CurrentUser,
    session: SessionDep,
):
    ext = await get_owned_or_404(session, Extension, ext_id, current_user.id)

    # Every child FK (AlertLog, AlertRule, FetchLog, InstallCountHistory) is
    # ON DELETE CASCADE, so deleting the extension removes its dependent rows.
    await session.delete(ext)
    await session.commit()
    return {"ok": True}


@router.post("/extensions/{ext_id}/refresh")
async def refresh_extension(
    ext_id: int,
    request: Request,
    current_user: CurrentUser,
    session: SessionDep,
) -> ExtensionOut:
    ext = await get_owned_or_404(session, Extension, ext_id, current_user.id)
    client: httpx.AsyncClient = request.app.state.http_client
    return ExtensionOut.from_db(await _fetch_and_score(ext, session, client))


@router.patch("/extensions/{ext_id}/watchlist")
async def toggle_watchlist(
    ext_id: int,
    body: WatchlistPatch,
    current_user: CurrentUser,
    session: SessionDep,
) -> ExtensionOut:
    ext = await get_owned_or_404(session, Extension, ext_id, current_user.id)
    ext.watchlist = body.watchlist
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ExtensionOut.from_db(ext)


@router.get("/extensions/{ext_id}/history")
async def get_history(
    ext_id: int,
    current_user: CurrentUser,
    session: SessionDep,
) -> list[HistoryPoint]:
    await get_owned_or_404(session, Extension, ext_id, current_user.id)
    rows = (
        await session.exec(
            select(InstallCountHistory)
            .where(InstallCountHistory.extension_id == ext_id)
            .order_by(InstallCountHistory.recorded_at)
        )
    ).all()
    return [HistoryPoint(recorded_at=r.recorded_at, install_count=r.install_count) for r in rows]
