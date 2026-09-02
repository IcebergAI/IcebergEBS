"""Audit trail of mutating actions (#34).

``record`` stages one ``AuditLog`` row on the **caller's** session and never
commits: the route's own ``commit()`` persists the row together with the change it
describes, so the two can't disagree (see ``models.AuditLog``). Call it right
before the commit that lands the mutation — after validation has passed, so a
rejected request writes nothing.

``AuditActor`` is a plain snapshot of *who* is acting. Routes that commit several
times in one request (bulk add, inventory) build it once up front, because every
commit expires the ``User`` ORM instance and re-reading ``current_user.username``
mid-loop would trigger a sync lazy refresh outside the async context.

Detail hygiene: ``detail`` is stored as JSON and rendered to admins/auditors.
Record **identifiers and field names**, never values that could be secrets — a
settings update records ``{"fields": [...]}``, not the proxy URL (which carries
credentials, #216), and password changes record nothing but the event.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import AuditLog, User


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who performed an action — captured before any commit expires the ORM row."""

    id: int | None
    username: str
    ip: str | None = None

    @classmethod
    def from_request(cls, user: User, request: Request | None) -> AuditActor:
        return cls(id=user.id, username=user.username, ip=client_ip(request))


def client_ip(request: Request | None) -> str | None:
    """The peer address uvicorn reports — behind Caddy that is the canonical
    single-value ``X-Forwarded-For`` it sets (a client-supplied header is
    discarded at the edge, #77), so this is not spoofable by the caller."""
    if request is None or request.client is None:
        return None
    return request.client.host


def build(
    actor: AuditActor | User,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    detail: dict[str, Any] | None = None,
    *,
    request: Request | None = None,
) -> AuditLog:
    """Construct an unattached audit row — for callers that hand it to a helper
    which owns the commit (``oidc_settings.update_settings(..., audit=row)``), so
    the row is only ever added once the helper knows a change is actually being
    written. Everyone else uses ``record``.

    ``actor`` may be the live ``User`` (its id/username are read immediately) or a
    pre-built ``AuditActor``. ``request`` supplies the client IP when a ``User`` is
    passed; an ``AuditActor`` already carries it.
    """
    if isinstance(actor, User):
        actor = AuditActor.from_request(actor, request)
    return AuditLog(
        actor_id=actor.id,
        actor=actor.username,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        detail=None if not detail else json.dumps(detail, sort_keys=True, default=str),
        ip=actor.ip,
    )


def record(
    session: AsyncSession,
    actor: AuditActor | User,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    detail: dict[str, Any] | None = None,
    *,
    request: Request | None = None,
) -> AuditLog:
    """Stage an audit row on ``session`` (no commit — see module docstring)."""
    row = build(actor, action, target_type, target_id, detail, request=request)
    session.add(row)
    return row
