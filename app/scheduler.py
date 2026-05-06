import json
import logging
from datetime import datetime, timezone

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine
from app.fetchers.base import FetchError
from app.fetchers.chrome import ChromeFetcher
from app.fetchers.edge import EdgeFetcher
from app.fetchers.vscode import VSCodeFetcher
from app.inspector import InspectorError, inspect_package
from app.models import Extension, FetchLog, InstallCountHistory
from app.scoring import compute_risk_score

logger = logging.getLogger(__name__)


def _get_fetcher(store: str, client: httpx.AsyncClient):
    if store == "chrome":
        return ChromeFetcher(client)
    if store == "vscode":
        return VSCodeFetcher(client)
    return EdgeFetcher(client)


async def _refresh_one(ext: Extension, session: AsyncSession, client: httpx.AsyncClient) -> None:
    fetcher = _get_fetcher(ext.store, client)
    score_before = ext.risk_score

    try:
        metadata, pkg_bytes = await fetcher.fetch(ext.extension_id)
    except FetchError as exc:
        logger.warning("Fetch failed for %s/%s: %s", ext.store, ext.extension_id, exc)
        session.add(FetchLog(
            extension_id=ext.id,
            success=False,
            error_message=str(exc),
            risk_score_before=score_before,
        ))
        return

    if metadata.install_count is not None:
        session.add(InstallCountHistory(
            extension_id=ext.id,
            install_count=metadata.install_count,
        ))

    history_rows = (await session.exec(
        select(InstallCountHistory)
        .where(InstallCountHistory.extension_id == ext.id)
        .order_by(InstallCountHistory.recorded_at)
    )).all()
    history = [r.install_count for r in history_rows]

    analysis = None
    if pkg_bytes:
        try:
            analysis = inspect_package(pkg_bytes)
        except InspectorError as exc:
            logger.debug("Inspector failed for %s: %s", ext.extension_id, exc)

    permissions = analysis.permissions if analysis else []
    host_permissions = analysis.host_permissions if analysis else []

    if analysis:
        if not metadata.version and analysis.version:
            metadata.version = analysis.version
        if not metadata.publisher and analysis.author:
            metadata.publisher = analysis.author

    publisher_changed = bool(
        ext.last_fetched_at and ext.publisher and ext.publisher != metadata.publisher
    )

    risk = compute_risk_score(
        permissions=permissions,
        host_permissions=host_permissions,
        install_count=metadata.install_count,
        install_history=history,
        publisher=metadata.publisher,
        publisher_changed=publisher_changed,
        publisher_verified=metadata.publisher_verified,
        last_updated=metadata.last_updated,
        analysis=analysis,
    )

    ext.name = metadata.name
    ext.publisher = metadata.publisher
    ext.description = metadata.description
    ext.version = metadata.version
    ext.install_count = metadata.install_count
    ext.last_updated = metadata.last_updated
    ext.permissions = json.dumps(permissions)
    ext.last_fetched_at = datetime.now(timezone.utc)
    ext.risk_score = risk.total
    ext.risk_detail = json.dumps(risk._asdict())
    if analysis:
        ext.package_analysis = json.dumps({
            "permissions": analysis.permissions,
            "host_permissions": analysis.host_permissions,
            "external_domains": analysis.external_domains,
            "uses_eval": analysis.uses_eval,
            "uses_remote_code": analysis.uses_remote_code,
            "obfuscation_score": analysis.obfuscation_score,
            "file_count": analysis.file_count,
            "total_size_bytes": analysis.total_size_bytes,
            "has_minified_code": analysis.has_minified_code,
            "manifest_version": analysis.manifest_version,
        })

    session.add(ext)
    session.add(FetchLog(
        extension_id=ext.id,
        success=True,
        risk_score_before=score_before,
        risk_score_after=risk.total,
    ))


async def refresh_watchlist(client: httpx.AsyncClient) -> None:
    logger.info("Starting watchlist refresh")
    async with AsyncSession(engine) as session:
        watchlist = (await session.exec(
            select(Extension).where(Extension.watchlist == True)
        )).all()

        for ext in watchlist:
            try:
                await _refresh_one(ext, session, client)
            except Exception as exc:
                logger.error("Unexpected error refreshing %s: %s", ext.extension_id, exc)

        await session.commit()
    logger.info("Watchlist refresh complete (%d extensions)", len(watchlist))


def create_scheduler(client: httpx.AsyncClient) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        refresh_watchlist,
        trigger="interval",
        minutes=settings.fetch_interval_minutes,
        args=[client],
        id="watchlist_refresh",
        replace_existing=True,
    )
    return scheduler
