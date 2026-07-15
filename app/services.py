import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone

import anyio.to_thread
import httpx
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers import get_fetcher
from app.inspector import InspectorError, PackageAnalysis, inspect_package
from app.models import Extension, FetchLog, InstallCountHistory
from app.notifications import ChangeEvent, detect_changes, fire_alerts
from app.scoring import compute_risk_score

logger = logging.getLogger(__name__)


async def fetch_and_store(
    ext: Extension,
    session: AsyncSession,
    client: httpx.AsyncClient,
) -> tuple[Extension, list[ChangeEvent]]:
    """Fetch metadata + package, run inspection and scoring, update the extension record.

    Adds a success FetchLog and stages all changes but does NOT commit — the caller
    decides when to commit (immediately for API routes, batched for the scheduler).

    Returns the updated extension and the list of detected change events. Alerts are
    deliberately NOT fired here: firing opens a second DB session, which would contend
    with this caller's still-open write transaction. The caller must commit first and
    then pass the returned events to ``fire_pending_alerts``.

    Raises FetchError if the remote fetch fails; the caller is responsible for adding
    a failure FetchLog and handling the error appropriately.
    """
    fetcher = get_fetcher(ext.store, client)
    score_before = ext.risk_score

    # Snapshot state before any mutations for change detection
    old_snap = ext.model_copy()

    metadata, pkg_bytes = await fetcher.fetch(ext.extension_id)

    if metadata.install_count is not None:
        session.add(
            InstallCountHistory(
                extension_id=ext.id,
                install_count=metadata.install_count,
            )
        )

    history_rows = (
        await session.exec(
            select(InstallCountHistory)
            .where(InstallCountHistory.extension_id == ext.id)
            .order_by(InstallCountHistory.recorded_at)
        )
    ).all()
    history = [r.install_count for r in history_rows]

    analysis: PackageAnalysis | None = None
    if pkg_bytes:
        try:
            # inspect_package runs ~20 regexes over up to 500 JS files of pure CPU.
            # Offload it so it doesn't stall the single-worker event loop (and the
            # scheduler) for the duration of analysis (issue #4).
            analysis = await anyio.to_thread.run_sync(inspect_package, pkg_bytes)
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

    publisher_changed = bool(ext.last_fetched_at and ext.publisher and ext.publisher != metadata.publisher)

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
    ext.store_url = metadata.store_url
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
        ext.package_analysis = json.dumps(
            {
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
            }
        )

    session.add(ext)
    session.add(
        FetchLog(
            extension_id=ext.id,
            success=True,
            risk_score_before=score_before,
            risk_score_after=risk.total,
        )
    )

    # Detect changes now (pre-fetch snapshot vs updated record), but let the caller
    # fire the alerts AFTER it commits — see the docstring and fire_pending_alerts.
    try:
        events = detect_changes(old_snap, ext)
    except Exception:
        logger.exception("Change detection failed for %s", ext.extension_id)
        events = []

    # Persist the pending events in the SAME session as the state change so they commit
    # atomically (#109). If the process dies before fire_pending_alerts runs, the marker
    # survives and the next cycle re-fires them; fire_pending_alerts clears it on success.
    ext.pending_alert_events = json.dumps([asdict(e) for e in events]) if events else None

    return ext, events


async def fire_pending_alerts(
    events: list[ChangeEvent],
    ext: Extension,
    engine: AsyncEngine,
    client: httpx.AsyncClient,
) -> None:
    """Fire alerts for events detected by ``fetch_and_store``.

    MUST be called only after the caller has committed; fire_alerts opens its own DB
    session, which must not run inside the caller's still-open write transaction.
    Never raises — a delivery or logging failure must not break the fetch pipeline.
    The extension's attributes must be loaded (refresh after commit) before calling,
    since fire_alerts reads them to build the webhook payload.
    """
    if not events:
        # No events to fire, but a stale marker (e.g. from an interrupted prior run with
        # no matching rules) should not linger — clear it so recovery doesn't retry forever.
        await _clear_pending_alerts(ext.id, engine)
        return
    try:
        await fire_alerts(events, ext, engine, client)
    except Exception:
        logger.exception(
            "Alert processing failed for %s — any delivered webhooks may not have been recorded in the alert log",
            ext.extension_id,
        )
        # Keep the durable marker so a shutdown-dropped alert is retried next cycle (#109).
        return
    # Delivered + recorded: clear the durable marker so it isn't re-fired.
    await _clear_pending_alerts(ext.id, engine)


async def _clear_pending_alerts(ext_id: int | None, engine: AsyncEngine) -> None:
    """Clear an extension's pending-alert marker in its own committed session (#109)."""
    if ext_id is None:
        return
    async with AsyncSession(engine) as session:
        ext = await session.get(Extension, ext_id)
        if ext is not None and ext.pending_alert_events is not None:
            ext.pending_alert_events = None
            await session.commit()


async def recover_pending_alerts(engine: AsyncEngine, client: httpx.AsyncClient) -> None:
    """Re-fire alerts persisted-but-not-delivered before a prior shutdown/crash (#109).

    Scans for extensions whose ``pending_alert_events`` marker is still set — meaning the
    process died between committing a state change and delivering its alert — and fires
    them. Called at startup and at the head of each refresh cycle. ``fire_pending_alerts``
    clears the marker on success, so this is idempotent and self-healing.
    """
    async with AsyncSession(engine) as session:
        pending = (await session.exec(select(Extension).where(Extension.pending_alert_events.is_not(None)))).all()

    for ext in pending:
        try:
            raw = json.loads(ext.pending_alert_events or "[]")
            events = [ChangeEvent(**e) for e in raw]
        except Exception:
            logger.exception("Discarding unparsable pending_alert_events for %s", ext.extension_id)
            await _clear_pending_alerts(ext.id, engine)
            continue
        logger.info("Recovering %d pending alert(s) for %s after restart", len(events), ext.extension_id)
        await fire_pending_alerts(events, ext, engine, client)
