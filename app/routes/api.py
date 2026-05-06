import json
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_auth
from app.database import get_session
from app.fetchers.base import FetchError
from app.models import Extension, FetchLog, InstallCountHistory
from app.services import fetch_and_store

router = APIRouter()

StoreType = Literal["chrome", "vscode", "edge"]


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ExtensionIn(BaseModel):
    store: StoreType
    extension_id: str  # raw ID or full store URL


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

    @classmethod
    def from_db(cls, ext: Extension) -> "ExtensionOut":
        perms = json.loads(ext.permissions or "[]")
        analysis_raw = json.loads(ext.package_analysis or "null")
        host_perms = analysis_raw.get("host_permissions", []) if analysis_raw else []
        detail = json.loads(ext.risk_detail or "null")
        risk_level = None
        if ext.risk_score is not None:
            if ext.risk_score >= 75:
                risk_level = "critical"
            elif ext.risk_score >= 50:
                risk_level = "high"
            elif ext.risk_score >= 25:
                risk_level = "medium"
            else:
                risk_level = "low"
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
            risk_level=risk_level,
        )


class WatchlistPatch(BaseModel):
    watchlist: bool


class HistoryPoint(BaseModel):
    recorded_at: datetime
    install_count: int


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
        ext = await fetch_and_store(ext, session, client)
    except FetchError as exc:
        session.add(FetchLog(
            extension_id=ext.id,
            success=False,
            error_message=str(exc),
            risk_score_before=score_before,
        ))
        await session.commit()
        raise HTTPException(status_code=502, detail=str(exc))
    await session.commit()
    await session.refresh(ext)
    return ext


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/extensions", response_model=list[ExtensionOut])
async def list_extensions(
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    rows = (await session.exec(select(Extension).order_by(Extension.added_at.desc()))).all()
    return [ExtensionOut.from_db(r) for r in rows]


@router.post("/extensions", response_model=ExtensionOut, status_code=201)
async def add_extension(
    body: ExtensionIn,
    request: Request,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    extension_id = normalise_extension_id(body.store, body.extension_id)

    existing = (await session.exec(
        select(Extension).where(
            Extension.store == body.store,
            Extension.extension_id == extension_id,
        )
    )).first()
    if existing:
        raise HTTPException(status_code=409, detail="Extension already tracked")

    ext = Extension(
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

    client: httpx.AsyncClient = request.app.state.http_client
    return ExtensionOut.from_db(await _fetch_and_score(ext, session, client))


@router.get("/extensions/{ext_id}", response_model=ExtensionOut)
async def get_extension(
    ext_id: int,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        raise HTTPException(status_code=404, detail="Not found")
    return ExtensionOut.from_db(ext)


@router.delete("/extensions/{ext_id}")
async def delete_extension(
    ext_id: int,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        raise HTTPException(status_code=404, detail="Not found")
    await session.delete(ext)
    await session.commit()
    return {"ok": True}


@router.post("/extensions/{ext_id}/refresh", response_model=ExtensionOut)
async def refresh_extension(
    ext_id: int,
    request: Request,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        raise HTTPException(status_code=404, detail="Not found")
    client: httpx.AsyncClient = request.app.state.http_client
    return ExtensionOut.from_db(await _fetch_and_score(ext, session, client))


@router.patch("/extensions/{ext_id}/watchlist", response_model=ExtensionOut)
async def toggle_watchlist(
    ext_id: int,
    body: WatchlistPatch,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        raise HTTPException(status_code=404, detail="Not found")
    ext.watchlist = body.watchlist
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ExtensionOut.from_db(ext)


@router.get("/extensions/{ext_id}/history", response_model=list[HistoryPoint])
async def get_history(
    ext_id: int,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        raise HTTPException(status_code=404, detail="Not found")
    rows = (await session.exec(
        select(InstallCountHistory)
        .where(InstallCountHistory.extension_id == ext_id)
        .order_by(InstallCountHistory.recorded_at)
    )).all()
    return [HistoryPoint(recorded_at=r.recorded_at, install_count=r.install_count) for r in rows]
