import json
import logging
from typing import Any

import httpx
from pydantic.dataclasses import dataclass
from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.models import AlertDestination, AlertLog, AlertRule, Extension
from app.scoring import risk_level as _risk_level
from app.webhooks import send_webhook

logger = logging.getLogger(__name__)


@dataclass
class ChangeEvent:
    """A detected extension change, also round-tripped through the durable
    pending-alert marker (services._parse_pending_events).

    A pydantic dataclass, not a plain one, so construction validates field
    presence *and* types in one place: ``event_type`` must be a real string
    (pydantic v2 does not coerce other types to str), because fire_alerts uses
    it in sets and as a dict key — an unhashable value sneaking in from a
    corrupt marker would crash delivery and re-loop forever (#197 review).
    Stays a dataclass (not BaseModel) so ``dataclasses.asdict()`` keeps working
    at the marker-serialization sites.
    """

    event_type: str
    old_value: Any
    new_value: Any


def _host_permissions(ext: Extension) -> frozenset[str]:
    """Host permissions recorded in the extension's stored package_analysis.

    Returns an empty set on missing/malformed analysis so change detection never
    raises. Like ext.permissions, package_analysis is only rewritten on a fresh
    successful inspection (see services.fetch_and_store), so a transient download
    failure leaves both stale and cannot produce a spurious permission_change.
    """
    data = ext.analysis_dict()  # decode + object-shape parse owned by the accessor (#167)
    if data is None:
        return frozenset()
    hosts = data.get("host_permissions", [])
    if not isinstance(hosts, list):
        return frozenset()
    return frozenset(str(h) for h in hosts)


def detect_changes(old: Extension, new: Extension) -> list[ChangeEvent]:
    """Compare two Extension snapshots and return triggered change events.

    Returns an empty list on the first fetch (old.last_fetched_at is None)
    since there is no prior state to compare against.
    """
    if old.last_fetched_at is None:
        return []

    events: list[ChangeEvent] = []

    old_level = _risk_level(old.risk_score)
    new_level = _risk_level(new.risk_score)
    if old_level is not None and new_level is not None and old_level != new_level:
        events.append(ChangeEvent("risk_level_change", old_level, new_level))

    if old.publisher and new.publisher and old.publisher != new.publisher:
        events.append(ChangeEvent("publisher_change", old.publisher, new.publisher))

    # Compare API permissions *and* host permissions. Host patterns (<all_urls>,
    # *://*/*, …) are stored separately inside package_analysis, not in
    # ext.permissions — gaining broad host access is the highest-signal capability
    # change an update can make, so it must trigger permission_change too (#60).
    old_perms = frozenset(old.permissions_list()) | _host_permissions(old)
    new_perms = frozenset(new.permissions_list()) | _host_permissions(new)
    if old_perms != new_perms:
        events.append(ChangeEvent("permission_change", sorted(old_perms), sorted(new_perms)))

    if old.version and new.version and old.version != new.version:
        events.append(ChangeEvent("new_version", old.version, new.version))

    return events


def _alert_text(event_type: str, name: str, old: object, new: object) -> str:
    if event_type == "risk_level_change":
        return f"IcebergEBS: {name} risk level changed {old} → {new}"
    if event_type == "publisher_change":
        return f'IcebergEBS: {name} publisher changed from "{old}" to "{new}"'
    if event_type == "permission_change":
        return f"IcebergEBS: {name} permissions changed"
    if event_type == "new_version":
        return f"IcebergEBS: {name} updated to version {new}"
    return f"IcebergEBS: {name} — {event_type}"


def build_alert_payload(
    *,
    text: str,
    event: str,
    ext_id: int | None,
    name: str,
    store: str,
    store_url: str,
    old: Any,
    new: Any,
    risk_score: int | None,
) -> dict[str, Any]:
    """Assemble the webhook payload for an alert.

    The single source of the on-the-wire alert shape, so the destination-test
    payload (``alerts.test_destination``) can't silently drift from what real
    alerts send — the "test" webhook is the real webhook by construction (#168).
    ``iceberg_ebs_url`` is included only when ``app_base_url`` is configured,
    exactly as real alerts do.
    """
    ext_payload: dict[str, Any] = {
        "id": ext_id,
        "name": name,
        "store": store,
        "store_url": store_url,
    }
    if settings.app_base_url:
        ext_payload["iceberg_ebs_url"] = f"{settings.app_base_url.rstrip('/')}/extensions/{ext_id}"
    return {
        "text": text,
        "event": event,
        "extension": ext_payload,
        "change": {"old": old, "new": new},
        "risk_score": risk_score,
    }


async def fire_alerts(
    events: list[ChangeEvent],
    extension: Extension,
    engine: AsyncEngine,
    client: httpx.AsyncClient,
) -> None:
    """Find alert rules matching the given events and POST webhook payloads.

    Every event is delivered against every matching rule — including multiple
    events of the same type, which the merged pending marker can hold (#144). Do
    not collapse to one event per type or the older undelivered event is lost.

    Uses its own dedicated session so AlertLog rows are committed immediately,
    independent of any caller transaction that might later be rolled back.
    """
    if not events or extension.user_id is None:
        return

    event_types = list({e.event_type for e in events})

    async with AsyncSession(engine) as session:
        rules = (
            await session.exec(
                select(AlertRule).where(
                    AlertRule.user_id == extension.user_id,
                    AlertRule.enabled == True,  # noqa: E712
                    AlertRule.event_type.in_(event_types),
                    or_(AlertRule.extension_id == None, AlertRule.extension_id == extension.id),  # noqa: E711
                )
            )
        ).all()

        if not rules:
            return

        # Batch load all destinations referenced by matching rules to avoid N+1 queries.
        dest_ids = list({r.destination_id for r in rules})
        dests = (await session.exec(select(AlertDestination).where(AlertDestination.id.in_(dest_ids)))).all()
        dest_map = {d.id: d for d in dests}

        # Group rules by the event type they fire on so EVERY event is delivered.
        # The merged pending marker (#109) can hold several events of one type — e.g.
        # new_version 1.0→1.1 (delivery failed, retained) then 1.1→1.2 — and firing
        # one event per rule dropped the older one with no AlertLog even though
        # fire_pending_alerts then clears the whole marker, losing it for good (#144).
        rules_by_type: dict[str, list[AlertRule]] = {}
        for rule in rules:
            rules_by_type.setdefault(rule.event_type, []).append(rule)

        logged = 0
        # Deliver in list order — oldest→newest, the merge's chronological order — so a
        # consumer learns every transition the extension passed through (e.g. a risk
        # level that went low→high→low), not just the final one.
        for event in events:
            for rule in rules_by_type.get(event.event_type, []):
                dest = dest_map.get(rule.destination_id)
                if not dest or not dest.enabled:
                    continue

                alert_text = _alert_text(event.event_type, extension.name, event.old_value, event.new_value)
                payload = build_alert_payload(
                    text=alert_text,
                    event=event.event_type,
                    ext_id=extension.id,
                    name=extension.name,
                    store=extension.store,
                    store_url=extension.store_url,
                    old=event.old_value,
                    new=event.new_value,
                    risk_score=extension.risk_score,
                )

                success = True
                error: str | None = None
                try:
                    resp = await send_webhook(client, dest.target, payload)
                    resp.raise_for_status()
                    logger.info(
                        "Alert webhook fired: event=%s ext=%d dest=%d status=%d",
                        event.event_type,
                        extension.id,
                        dest.id,
                        resp.status_code,
                    )
                except Exception as exc:
                    success = False
                    error = str(exc)[:2000]
                    logger.warning(
                        "Alert webhook failed: event=%s ext=%d dest=%d error=%s",
                        event.event_type,
                        extension.id,
                        dest.id,
                        exc,
                    )

                session.add(
                    AlertLog(
                        rule_id=rule.id,
                        destination_id=dest.id,
                        extension_id=extension.id,
                        user_id=extension.user_id,
                        event_type=event.event_type,
                        detail=json.dumps({"old": event.old_value, "new": event.new_value}),
                        success=success,
                        error=error,
                    )
                )
                logged += 1

        try:
            await session.commit()
        except Exception:
            # The webhooks above were already delivered; if persisting the
            # AlertLog rows fails (e.g. a missing column from a half-applied
            # migration) the history would silently diverge from what was sent.
            # Surface it explicitly rather than letting the caller log a generic
            # trace, then re-raise so the failure is not mistaken for success.
            logger.exception(
                "Failed to record %d AlertLog row(s) for ext=%s after delivering "
                "webhooks — alert history will be incomplete",
                logged,
                extension.id,
            )
            raise
