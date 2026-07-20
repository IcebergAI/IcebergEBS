import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import anyio.to_thread
import httpx
from pydantic import ValidationError
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.fetchers import get_fetcher
from app.fetchers.base import ExtensionMetadata
from app.inspector import InspectorError, PackageAnalysis, inspect_package
from app.models import Extension, FetchLog, InstallCountHistory
from app.notifications import ChangeEvent, detect_changes, fire_alerts
from app.scoring import RiskDetail, compute_risk_score
from app.utils import json_list

logger = logging.getLogger(__name__)


@dataclass
class _EffectiveValues:
    """The values actually scored and stored for a fetch, after the keep-stale
    fallback rules have been applied (see ``_effective_values``)."""

    permissions: list[str]
    host_permissions: list[str]
    publisher: str
    publisher_changed: bool
    install_count: int | None
    last_updated: datetime | None


async def _stage_install_reading(session: AsyncSession, ext: Extension, metadata: ExtensionMetadata) -> list[int]:
    """Stage this fetch's install-count reading (when present) and return the
    install-count history ``score_popularity`` needs — oldest→newest, so
    ``history[-2]`` is the reading immediately before the current one.

    score_popularity's sudden-drop check only compares the current reading against
    the immediately preceding one (history[-2]), so load just the two most recent
    stored counts instead of scanning the whole install-count history — which is
    unbounded when retention is disabled (the default) and was being fully hydrated
    on every refresh of every watchlist extension, O(watchlist × history) per
    scheduler cycle (#146). Query column-only and before staging the new row, so the
    "previous" reading is the last real fetch rather than the row we're about to add.
    """
    previous_counts = (
        await session.exec(
            select(InstallCountHistory.install_count)
            .where(InstallCountHistory.extension_id == ext.id)
            .order_by(InstallCountHistory.recorded_at.desc(), InstallCountHistory.id.desc())
            .limit(2)
        )
    ).all()

    if metadata.install_count is not None:
        session.add(InstallCountHistory(extension_id=ext.id, install_count=metadata.install_count))
        # Ascending (oldest→newest) with the new reading last, so history[-2] is
        # the most recent stored count — the ordering score_popularity expects.
        return [*reversed(previous_counts), metadata.install_count]
    # No new reading this cycle: the stored counts alone, oldest→newest.
    return list(reversed(previous_counts))


def _effective_values(
    ext: Extension, metadata: ExtensionMetadata, analysis: PackageAnalysis | None
) -> _EffectiveValues:
    """Resolve the values actually scored + stored, applying the keep-stale
    fallbacks so a partial or failed fetch can't clobber good data or fire spurious
    alerts.

    When analysis is unavailable, fall back to stored values so that a transient
    package download failure doesn't look like permissions being removed and trigger
    spurious permission_change / risk_level_change alerts.

    A 200-status scrape can still be a partial parse (publisher="",
    install_count=None, last_updated=None — Chrome HTML never raises on a shifted
    layout). Like version/permissions, fall back to the stored values so one bad
    response can't swing the score (~+31 across publisher/popularity/staleness) and
    fire a spurious risk_level_change alert (#142). The manifest author fills the
    publisher gap only when no store-sourced publisher has ever been seen — it must
    never override a stored one, or an author/publisher mismatch would flap
    publisher_change alerts on every partial parse. publisher_changed likewise
    requires a non-empty store-sourced publisher: an empty parse is not a change
    signal.
    """
    if analysis:
        permissions: list[str] = analysis.permissions
        host_permissions: list[str] = analysis.host_permissions
    else:
        permissions = ext.permissions_list()
        # Shape-guarded accessor (#291): a stored host_permissions that is a string (partial
        # write / manual edit) would otherwise flow into score_permissions' set(...) and
        # iterate char-by-char — a silently wrong score that persists across keep-stale
        # refreshes. Same guard the notifications diff and the JSON DTO use.
        host_permissions = ext.host_permissions_list()

    publisher_changed = bool(
        ext.last_fetched_at and ext.publisher and metadata.publisher and ext.publisher != metadata.publisher
    )
    publisher = metadata.publisher or ext.publisher or (analysis.author if analysis else "")
    install_count = metadata.install_count if metadata.install_count is not None else ext.install_count
    last_updated = metadata.last_updated or ext.last_updated

    return _EffectiveValues(
        permissions=permissions,
        host_permissions=host_permissions,
        publisher=publisher,
        publisher_changed=publisher_changed,
        install_count=install_count,
        last_updated=last_updated,
    )


def _apply_fetch_results(
    ext: Extension,
    metadata: ExtensionMetadata,
    analysis: PackageAnalysis | None,
    effective: _EffectiveValues,
    risk: RiskDetail,
) -> None:
    """Write the fetched + scored values onto the extension row. Mirrors the
    keep-stale guards in ``_effective_values``: version / permissions /
    package_analysis are only overwritten from a fresh successful source, so a
    partial parse or a failed package download can't erase good data or fire
    spurious change alerts (#142)."""
    # name/description are deliberately unguarded (cosmetic, no score or alert
    # impact) — a partial Chrome parse can transiently persist name=extension_id
    # until the next good fetch.
    ext.name = metadata.name
    ext.publisher = effective.publisher
    ext.description = metadata.description
    ext.store_url = metadata.store_url
    # Only update version when the store returns a non-empty value; keeping
    # the stored version avoids spurious new_version alerts when Chrome HTML
    # scraping temporarily fails and returns an empty string.
    if metadata.version:
        ext.version = metadata.version
    # Persist the same effective values that were scored, so risk_detail stays
    # consistent with the stored row (#142).
    ext.install_count = effective.install_count
    ext.last_updated = effective.last_updated
    if analysis:
        # Only update stored permissions from a fresh successful inspection;
        # keeping stale values avoids spurious permission_change alerts when
        # the package download temporarily fails.
        ext.permissions = json.dumps(effective.permissions)
    ext.last_fetched_at = datetime.now(timezone.utc)
    ext.risk_score = risk.total
    ext.risk_detail = json.dumps(risk._asdict())
    if analysis:
        # Serialization lives on the dataclass so the stored field list can't
        # drift from the render defaults in routes/ui.py (#164).
        ext.package_analysis = json.dumps(analysis.to_json_dict())


def _parse_pending_events(raw: str | None, ext_id: int | None) -> list[ChangeEvent]:
    """Best-effort decode of a pending-alert marker string into ``ChangeEvent``s.

    The single defensive parse for the JSON-in-str ``pending_alert_events`` column (#167,
    #197): a marker corrupted by a partial write or hand-edit must never crash the fetch
    nor loop forever undelivered. Drops any non-dict entry (`utils.json_list` already
    returns ``[]`` on unparsable / non-list JSON) and any dict that isn't a well-formed
    event, logging what it discards. The remaining events are exactly what can be delivered.

    ``ChangeEvent`` is a pydantic dataclass, so construction itself rejects both shapes
    of malformed entry — wrong/missing/extra keys and wrong field *types* (notably a
    non-string ``event_type``, which would be unhashable in ``fire_alerts``' set/dict
    keying and re-crash delivery every cycle forever — #197 review). One except clause
    is the whole guard.
    """
    result: list[ChangeEvent] = []
    for e in json_list(raw, "pending_alert_events", ext_id):
        if not isinstance(e, dict):
            continue
        try:
            event = ChangeEvent(**e)
        except (ValidationError, TypeError):
            logger.warning("Dropping malformed pending alert event for extension %s", ext_id)
            continue
        result.append(event)
    return result


async def _merge_pending_events(session: AsyncSession, ext: Extension, events: list[ChangeEvent]) -> list[ChangeEvent]:
    """Merge freshly-detected events into the durable pending-alert marker under a
    row lock, and return the full pending set the caller should fire.

    Persist the pending events in the SAME transaction as the state change so they
    commit atomically (#109). If the process dies before fire_pending_alerts runs,
    the marker survives and the next cycle re-fires them; fire_pending_alerts clears
    it on success.

    MERGE rather than overwrite: a prior delivery may have failed and intentionally
    left its events in the marker for retry. Overwriting (with the new events, or
    None when nothing changed) would silently drop them — and the manual-refresh
    path doesn't run recovery first, so it can't rely on the scheduler having
    drained them.

    The merge is a read-modify-write, so do it under a row lock, or two refreshes of
    the SAME extension that overlap (a manual API refresh racing the scheduler cycle)
    could each read the old marker and last-writer-wins would drop one side's events
    (#109 review). Flush this row's other changes first (also assigns ext.id on a
    first-time insert), then SELECT ... FOR UPDATE the marker: the locking read
    returns the *current committed* value — not the stale one loaded before a
    concurrent writer committed — and the lock is held until the caller commits, so
    the other writer's events are appended, never clobbered. We return the full
    merged set so the caller fires everything pending, not just this refresh's new
    events.
    """
    new_events = [asdict(e) for e in events]
    await session.flush()
    locked_marker = (
        await session.exec(select(Extension.pending_alert_events).where(Extension.id == ext.id).with_for_update())
    ).one()
    # Decode the prior marker defensively via the shared parser: a corrupt marker
    # (non-list, or holding non-dict / malformed entries) must not fail the fetch — the
    # bare json.loads here previously let a valid-but-wrong-shape marker (e.g. "{}" or
    # '["junk"]') raise TypeError at the `prior + new_events` / `ChangeEvent(**e)` lines
    # below, 500-ing the refresh (#197). Round-tripping through _parse_pending_events also
    # cleanses the junk out of the re-persisted marker so it can't accumulate.
    prior = [asdict(e) for e in _parse_pending_events(locked_marker, ext.id)]
    pending = prior + new_events
    ext.pending_alert_events = json.dumps(pending) if pending else None
    return [ChangeEvent(**e) for e in pending]


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

    history = await _stage_install_reading(session, ext, metadata)

    analysis: PackageAnalysis | None = None
    if pkg_bytes:
        try:
            # inspect_package runs ~20 regexes over up to 500 JS files of pure CPU.
            # Offload it so it doesn't stall the single-worker event loop (and the
            # scheduler) for the duration of analysis (issue #4).
            analysis = await anyio.to_thread.run_sync(inspect_package, pkg_bytes)
        except InspectorError as exc:
            logger.debug("Inspector failed for %s: %s", ext.extension_id, exc)

    effective = _effective_values(ext, metadata, analysis)

    risk = compute_risk_score(
        permissions=effective.permissions,
        host_permissions=effective.host_permissions,
        install_count=effective.install_count,
        install_history=history,
        publisher=effective.publisher,
        publisher_changed=effective.publisher_changed,
        publisher_verified=metadata.publisher_verified,
        last_updated=effective.last_updated,
        analysis=analysis,
    )

    _apply_fetch_results(ext, metadata, analysis, effective, risk)
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

    events = await _merge_pending_events(session, ext, events)
    return ext, events


async def fire_pending_alerts(
    events: list[ChangeEvent],
    ext: Extension,
    engine: AsyncEngine,
    client: httpx.AsyncClient,
    expected_marker: str | None = None,
) -> None:
    """Fire alerts for events detected by ``fetch_and_store``.

    MUST be called only after the caller has committed; fire_alerts opens its own DB
    session, which must not run inside the caller's still-open write transaction.
    Never raises — a delivery or logging failure must not break the fetch pipeline.
    The extension's attributes must be loaded (refresh after commit) before calling,
    since fire_alerts reads them to build the webhook payload.

    ``expected_marker`` is the exact stored marker string these events were derived from,
    used for the compare-and-clear. The normal pipeline (events == the full re-persisted
    marker) omits it and we re-serialize ``events`` — an identical string. The recovery
    path passes the raw marker explicitly because it may have delivered a *filtered subset*
    of a corrupt marker (junk entries dropped); clearing must then match the whole raw
    marker, not the filtered subset, or the marker never clears and re-fires every cycle
    forever (#197).
    """
    if not events:
        return
    # Snapshot exactly what we're about to clear against: the raw marker when given, else
    # the serialization of what we fired (identical for the normal, unfiltered path). We
    # clear the marker only if it still holds this same value (compare-and-clear below).
    fired = expected_marker if expected_marker is not None else json.dumps([asdict(e) for e in events])
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
    await _clear_pending_alerts(ext.id, engine, fired)


async def _clear_pending_alerts(ext_id: int | None, engine: AsyncEngine, expected: str) -> None:
    """Clear an extension's pending-alert marker with an atomic compare-and-clear (#109).

    A single conditional UPDATE (``... WHERE pending_alert_events = :expected``) wipes the
    marker only if it still holds exactly what we delivered. Doing the compare inside the
    WHERE — evaluated under the row's write lock at UPDATE time — rather than reading then
    writing in Python closes the TOCTOU window where a concurrent refresh appends new events
    between the read and the clear, which a blind read-then-clear would erase (#109 review).
    If the marker no longer matches, it's left for the next cycle to deliver.
    """
    if ext_id is None:
        return
    async with AsyncSession(engine) as session:
        await session.execute(
            sa_update(Extension)
            .where(Extension.id == ext_id, Extension.pending_alert_events == expected)
            .values(pending_alert_events=None)
        )
        await session.commit()


async def recover_pending_alerts(engine: AsyncEngine, client: httpx.AsyncClient) -> None:
    """Re-fire alerts persisted-but-not-delivered before a prior shutdown/crash (#109).

    Scans for extensions whose ``pending_alert_events`` marker is still set — meaning the
    process died between committing a state change and delivering its alert — and fires
    them. Called at the head of each scheduler refresh cycle (only — not at startup, so it
    can't block the server from binding, #155). ``fire_pending_alerts`` clears the marker on
    success, so this is idempotent and self-healing.
    """
    async with AsyncSession(engine) as session:
        ext_ids = (await session.exec(select(Extension.id).where(Extension.pending_alert_events.is_not(None)))).all()

    for ext_id in ext_ids:
        # Per-extension isolation (#282 review): recovery runs at the head of the cycle,
        # before the guarded refresh loop, so an unhandled error here — a concurrent DELETE
        # between get and refresh, or a transient error in delivery/clear — would escape
        # recover_pending_alerts and abort the whole cycle, starving every refresh and the
        # /readyz heartbeat. Isolate each extension: the durable marker survives, so the
        # next cycle retries this one.
        try:
            async with AsyncSession(engine) as session:
                ext = await session.get(Extension, ext_id)
                if ext is None or ext.pending_alert_events is None:
                    continue
                raw = ext.pending_alert_events
                # _parse_pending_events owns the full defensive decode (#167, #197): it drops
                # both non-dict entries and malformed event dicts rather than raising, so one
                # bad entry no longer discards the whole marker or crashes recovery.
                events = _parse_pending_events(raw, ext.id)
                if not events:
                    # Nothing deliverable (empty "[]", or a wholly-corrupt marker) — compare-and-
                    # clear the raw marker so it doesn't linger (and so a concurrent append isn't
                    # erased).
                    await _clear_pending_alerts(ext_id, engine, raw)
                    continue
                logger.info("Recovering %d pending alert(s) for %s after restart", len(events), ext.extension_id)
                # Mirror _refresh_one exactly: commit + refresh so ext is attached and fresh
                # when fire_pending_alerts (which opens its own session) reads its attributes —
                # firing off a detached/uncommitted object trips MissingGreenlet.
                await session.commit()
                await session.refresh(ext)
                # Clear against the RAW marker, not the (possibly filtered) fired subset: if the
                # marker held junk alongside valid events, we deliver the valid ones and still
                # clear the whole marker — otherwise the compare-and-clear never matches and the
                # valid events re-fire every cycle forever (#197).
                await fire_pending_alerts(events, ext, engine, client, expected_marker=raw)
        except Exception:
            logger.exception("Pending-alert recovery failed for ext_id=%d; continuing", ext_id)
            continue
