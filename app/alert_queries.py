"""Shared alert-log query/serialization layer (#149).

`get_alert_log` is consumed by both the JSON API (`routes/alerts.py`'s
`/alerts/log`) and the server-side dashboard render (`routes/ui.py`). It lived
inside the `routes/alerts.py` HTTP-route module and was reached cross-module by
`routes/ui.py`; extracting it into a neutral module (mirroring how #163 pulled
the extension-query layer out of `routes/api.py` into `app.extension_queries`)
keeps the shared query out of the route module so a refactor of the routes
can't silently break the dashboard.
"""

from sqlalchemy import or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import AlertDestination, AlertLog, AlertRule, Extension


async def get_alert_log(user_id: int, session: AsyncSession, limit: int = 50) -> list[dict]:
    """Shared helper used by both the JSON API and the server-side page render."""
    # Load current rules so legacy logs (pre-migration, no user_id) are still found.
    rules = (await session.exec(select(AlertRule).where(AlertRule.user_id == user_id))).all()
    rule_map = {r.id: r for r in rules}
    rule_ids = list(rule_map.keys())

    # New logs carry user_id directly; legacy logs are matched via their rule_id.
    if rule_ids:
        log_filter = or_(AlertLog.user_id == user_id, AlertLog.rule_id.in_(rule_ids))
    else:
        log_filter = AlertLog.user_id == user_id

    logs = (await session.exec(select(AlertLog).where(log_filter).order_by(AlertLog.sent_at.desc()).limit(limit))).all()
    if not logs:
        return []

    # Batch load snapshot destinations (stored on new logs).
    snap_dest_ids = list({log.destination_id for log in logs if log.destination_id is not None})
    snap_dest_map: dict[int, AlertDestination] = {}
    if snap_dest_ids:
        snap_dests = (await session.exec(select(AlertDestination).where(AlertDestination.id.in_(snap_dest_ids)))).all()
        snap_dest_map = {d.id: d for d in snap_dests}

    # Batch load current rule destinations as a fallback for legacy logs.
    rule_dest_ids = list({r.destination_id for r in rules})
    rule_dest_map: dict[int, AlertDestination] = {}
    if rule_dest_ids:
        rule_dests = (await session.exec(select(AlertDestination).where(AlertDestination.id.in_(rule_dest_ids)))).all()
        rule_dest_map = {d.id: d for d in rule_dests}

    ext_ids = list({log.extension_id for log in logs})
    exts = (await session.exec(select(Extension).where(Extension.id.in_(ext_ids)))).all()
    ext_map = {e.id: e for e in exts}

    result = []
    for log in logs:
        # Prefer the destination snapshot stored at fire time; fall back to
        # the current rule's destination for rows written before the migration.
        if log.destination_id is not None:
            dest = snap_dest_map.get(log.destination_id)
        elif log.rule_id is not None and log.rule_id in rule_map:
            rule = rule_map[log.rule_id]
            dest = rule_dest_map.get(rule.destination_id)
        else:
            dest = None

        ext = ext_map.get(log.extension_id)
        result.append(
            {
                "id": log.id,
                "sent_at": log.sent_at.isoformat(),
                "event_type": log.event_type,
                "extension_id": log.extension_id,
                "ext_name": (ext.name or ext.extension_id) if ext else f"Extension {log.extension_id}",
                "dest_label": dest.label if dest else "—",
                "success": log.success,
                "error": log.error,
            }
        )
    return result
