import json
import logging
import re
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_api_auth
from app.database import engine, get_session
from app.fetchers.base import FetchError
from app.models import AlertLog, AlertRule, Extension, FetchLog, InstallCountHistory, User
from app.scoring import risk_level
from app.services import fetch_and_store, fire_pending_alerts
from app.threat_intel import build_threat_intel_indicators

router = APIRouter()

StoreType = Literal["chrome", "vscode", "edge"]


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
    def from_db(cls, ext: Extension) -> "ExtensionOut":
        perms = json.loads(ext.permissions or "[]")
        analysis_raw = json.loads(ext.package_analysis or "null")
        host_perms = analysis_raw.get("host_permissions", []) if analysis_raw else []
        findings = analysis_raw.get("findings", []) if analysis_raw else []
        threat_intel_indicators = build_threat_intel_indicators(analysis_raw)
        detail = json.loads(ext.risk_detail or "null")
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/extensions", response_model=list[ExtensionOut])
async def list_extensions(
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    rows = (await session.exec(
        select(Extension)
        .where(Extension.user_id == current_user.id)
        .order_by(Extension.added_at.desc())
    )).all()
    return [ExtensionOut.from_db(r) for r in rows]


@router.post("/extensions", response_model=ExtensionOut, status_code=201)
async def add_extension(
    body: ExtensionIn,
    request: Request,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    extension_id = normalise_extension_id(body.store, body.extension_id)
    _validate_extension_id(body.store, extension_id)

    existing = (await session.exec(
        select(Extension).where(
            Extension.user_id == current_user.id,
            Extension.store == body.store,
            Extension.extension_id == extension_id,
        )
    )).first()
    if existing:
        raise HTTPException(status_code=409, detail="Extension already tracked")

    ext = Extension(
        user_id=current_user.id,
        store=body.store,
        extension_id=extension_id,
        name=extension_id,
        publisher="",
        version="",
        store_url="",
    )
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    ext_id = ext.id

    client: httpx.AsyncClient = request.app.state.http_client
    try:
        scored = await _fetch_and_score(ext, session, client)
    except HTTPException:
        # The first fetch failed — discard the placeholder row (and any failure
        # FetchLog created during the attempt) so the user isn't left with an
        # unanalysed extension stuck in their list.
        for fl in (await session.exec(
            select(FetchLog).where(FetchLog.extension_id == ext_id)
        )).all():
            await session.delete(fl)
        orphan = await session.get(Extension, ext_id)
        if orphan is not None:
            await session.delete(orphan)
        await session.commit()
        raise
    return ExtensionOut.from_db(scored)


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
