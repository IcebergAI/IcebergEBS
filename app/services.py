import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers import get_fetcher
from app.fetchers.base import FetchError
from app.inspector import InspectorError, PackageAnalysis, inspect_package
from app.models import Extension, FetchLog, InstallCountHistory
from app.notifications import detect_changes, fire_alerts
from app.scoring import compute_risk_score

logger = logging.getLogger(__name__)


async def fetch_and_store(
    ext: Extension,
    session: AsyncSession,
    client: httpx.AsyncClient,
    engine: AsyncEngine | None = None,
) -> Extension:
    """Fetch metadata + package, run inspection and scoring, update the extension record.

    Adds a success FetchLog and stages all changes but does NOT commit — the caller
    decides when to commit (immediately for API routes, batched for the scheduler).
    AlertLog entries from fire_alerts are committed immediately in their own session.

    Raises FetchError if the remote fetch fails; the caller is responsible for adding
    a failure FetchLog and handling the error appropriately.
    """
    fetcher = get_fetcher(ext.store, client)
    score_before = ext.risk_score

    # Snapshot state before any mutations for change detection
    old_snap = ext.model_copy()

    metadata, pkg_bytes = await fetcher.fetch(ext.extension_id)

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

    analysis: PackageAnalysis | None = None
    if pkg_bytes:
        try:
            analysis = inspect_package(pkg_bytes)
        except InspectorError as exc:
            logger.debug("Inspector failed for %s: %s", ext.extension_id, exc)

    if analysis:
        if not metadata.publisher and analysis.author:
            metadata.publisher = analysis.author

    # When analysis is unavailable, fall back to stored values so that a
    # transient package download failure doesn't look like permissions being
    # removed and trigger spurious permission_change / risk_level_change alerts.
    if analysis:
        permissions: list[str] = analysis.permissions
        host_permissions: list[str] = analysis.host_permissions
    else:
        permissions = json.loads(ext.permissions or "[]")
        stored_pkg = json.loads(ext.package_analysis or "null") or {}
        host_permissions = stored_pkg.get("host_permissions", [])

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
    # Only update version when the store returns a non-empty value; keeping
    # the stored version avoids spurious new_version alerts when Chrome HTML
    # scraping temporarily fails and returns an empty string.
    if metadata.version:
        ext.version = metadata.version
    ext.install_count = metadata.install_count
    ext.last_updated = metadata.last_updated
    if analysis:
        # Only update stored permissions from a fresh successful inspection;
        # keeping stale values avoids spurious permission_change alerts when
        # the package download temporarily fails.
        ext.permissions = json.dumps(permissions)
    ext.last_fetched_at = datetime.now(timezone.utc)
    ext.risk_score = risk.total
    ext.risk_detail = json.dumps(risk._asdict())
    if analysis:
        ext.package_analysis = json.dumps({
            "permissions": analysis.permissions,
            "host_permissions": analysis.host_permissions,
            "external_domains": analysis.external_domains,
            "external_urls": analysis.external_urls,
            "network_callout_urls": analysis.network_callout_urls,
            "package_sha256": analysis.package_sha256,
            "archive_sha256": analysis.archive_sha256,
            "uses_eval": analysis.uses_eval,
            "uses_remote_code": analysis.uses_remote_code,
            "obfuscation_score": analysis.obfuscation_score,
            "file_count": analysis.file_count,
            "total_size_bytes": analysis.total_size_bytes,
            "has_minified_code": analysis.has_minified_code,
            "manifest_version": analysis.manifest_version,
            "findings": [asdict(finding) for finding in analysis.findings],
        })

    session.add(ext)
    session.add(FetchLog(
        extension_id=ext.id,
        success=True,
        risk_score_before=score_before,
        risk_score_after=risk.total,
    ))

    try:
        events = detect_changes(old_snap, ext)
        if engine is not None:
            await fire_alerts(events, ext, engine, client)
    except Exception as exc:
        logger.exception("Alert processing failed for %s", ext.extension_id)

    return ext
