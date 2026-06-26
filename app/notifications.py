import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx
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
    event_type: str
    old_value: Any
    new_value: Any


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

    old_perms = frozenset(json.loads(old.permissions or "[]"))
    new_perms = frozenset(json.loads(new.permissions or "[]"))
    if old_perms != new_perms:
        events.append(ChangeEvent("permission_change", sorted(old_perms), sorted(new_perms)))

    if old.version and new.version and old.version != new.version:
        events.append(ChangeEvent("new_version", old.version, new.version))

    return events


def _alert_text(event_type: str, name: str, old: object, new: object) -> str:
    if event_type == "risk_level_change":
        return f"Marvin: {name} risk level changed {old} → {new}"
    if event_type == "publisher_change":
        return f'Marvin: {name} publisher changed from "{old}" to "{new}"'
    if event_type == "permission_change":
        return f"Marvin: {name} permissions changed"
    if event_type == "new_version":
        return f"Marvin: {name} updated to version {new}"
    return f"Marvin: {name} — {event_type}"


async def fire_alerts(
    events: list[ChangeEvent],
    extension: Extension,
    engine: AsyncEngine,
    client: httpx.AsyncClient,
) -> None:
    """Find alert rules matching the given events and POST webhook payloads.

    Uses its own dedicated session so AlertLog rows are committed immediately,
    independent of any caller transaction that might later be rolled back.
    """
    if not events or extension.user_id is None:
        return

    event_map = {e.event_type: e for e in events}
    event_types = list(event_map.keys())

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

        ext_payload = {
            "id": extension.id,
            "name": extension.name,
            "store": extension.store,
            "store_url": extension.store_url,
        }
        if settings.app_base_url:
            ext_payload["marvin_url"] = f"{settings.app_base_url.rstrip('/')}/extensions/{extension.id}"

        for rule in rules:
            dest = dest_map.get(rule.destination_id)
            if not dest or not dest.enabled:
                continue

            event = event_map[rule.event_type]
            alert_text = _alert_text(event.event_type, extension.name, event.old_value, event.new_value)
            payload = {
                "text": alert_text,
                "event": event.event_type,
                "extension": ext_payload,
                "change": {"old": event.old_value, "new": event.new_value},
                "risk_score": extension.risk_score,
            }

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
                len(rules),
                extension.id,
            )
            raise
