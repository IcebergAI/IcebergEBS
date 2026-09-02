"""Read side of the audit trail (#34): ``GET /api/audit``.

Readable by **admin and auditor** (``AuditReader``) — reading other users' actions
is the auditor role's entire purpose, and is exactly what an analyst does not get.
Rows are never written through the API; every writer is a route-side
``audit.record`` (see ``app/audit.py``).
"""

from datetime import datetime
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict
from sqlmodel import select

from app.deps import AuditReader, SessionDep
from app.models import AuditLog

router = APIRouter(prefix="/api", tags=["audit"])

DEFAULT_LIMIT = 100
MAX_LIMIT = 500


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor_id: Optional[int]
    actor: str
    action: str
    target_type: str
    target_id: Optional[str]
    detail: dict[str, Any]
    ip: Optional[str]

    @classmethod
    def from_db(cls, row: AuditLog) -> "AuditLogOut":
        return cls(
            id=row.id or 0,
            at=row.at,
            actor_id=row.actor_id,
            actor=row.actor,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            detail=row.detail_dict(),
            ip=row.ip,
        )


@router.get("/audit")
async def list_audit_log(
    _: AuditReader,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    actor: Annotated[str | None, Query(description="Exact actor username")] = None,
    action: Annotated[str | None, Query(description="Exact action, e.g. extension.delete")] = None,
    target_type: Annotated[str | None, Query()] = None,
    target_id: Annotated[str | None, Query()] = None,
    since: Annotated[datetime | None, Query(description="Only rows at/after this time")] = None,
) -> list[AuditLogOut]:
    """Newest-first page of the trail, bounded like ``/alerts/log`` (#284)."""
    stmt = select(AuditLog)
    if actor is not None:
        stmt = stmt.where(AuditLog.actor == actor)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if target_type is not None:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id is not None:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if since is not None:
        stmt = stmt.where(AuditLog.at >= since)
    rows = (await session.exec(stmt.order_by(AuditLog.at.desc(), AuditLog.id.desc()).limit(limit).offset(offset))).all()
    return [AuditLogOut.from_db(r) for r in rows]
