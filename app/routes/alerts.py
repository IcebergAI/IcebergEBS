from datetime import datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_auth
from app.config import settings
from app.database import get_session
from app.models import AlertDestination, AlertLog, AlertRule, Extension, User

router = APIRouter()

VALID_EVENT_TYPES = {"risk_level_change", "publisher_change", "permission_change", "new_version"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DestinationOut(BaseModel):
    id: int
    label: str
    target: str
    enabled: bool
    created_at: datetime


class DestinationIn(BaseModel):
    label: str
    target: str  # webhook URL
    enabled: bool = True


class DestinationPatch(BaseModel):
    label: str | None = None
    target: str | None = None
    enabled: bool | None = None


class RuleOut(BaseModel):
    id: int
    destination_id: int
    extension_id: int | None
    event_type: str
    enabled: bool
    created_at: datetime


class RuleIn(BaseModel):
    destination_id: int
    event_type: str
    extension_id: int | None = None
    enabled: bool = True


class RulePatch(BaseModel):
    destination_id: int | None = None
    enabled: bool | None = None


# ---------------------------------------------------------------------------
# Destinations
# ---------------------------------------------------------------------------

@router.get("/alerts/destinations", response_model=list[DestinationOut])
async def list_destinations(
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    dests = (await session.exec(
        select(AlertDestination)
        .where(AlertDestination.user_id == current_user.id)
        .order_by(AlertDestination.created_at)
    )).all()
    return [DestinationOut(id=d.id, label=d.label, target=d.target, enabled=d.enabled, created_at=d.created_at) for d in dests]


@router.post("/alerts/destinations", response_model=DestinationOut, status_code=201)
async def create_destination(
    body: DestinationIn,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    dest = AlertDestination(
        user_id=current_user.id,
        label=body.label,
        target=body.target,
        enabled=body.enabled,
    )
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut(id=dest.id, label=dest.label, target=dest.target, enabled=dest.enabled, created_at=dest.created_at)


@router.patch("/alerts/destinations/{dest_id}", response_model=DestinationOut)
async def update_destination(
    dest_id: int,
    body: DestinationPatch,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    dest = await session.get(AlertDestination, dest_id)
    if not dest or dest.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    if body.label is not None:
        dest.label = body.label
    if body.target is not None:
        dest.target = body.target
    if body.enabled is not None:
        dest.enabled = body.enabled
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut(id=dest.id, label=dest.label, target=dest.target, enabled=dest.enabled, created_at=dest.created_at)


@router.delete("/alerts/destinations/{dest_id}")
async def delete_destination(
    dest_id: int,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    dest = await session.get(AlertDestination, dest_id)
    if not dest or dest.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    # Remove dependent rules first
    rules = (await session.exec(
        select(AlertRule).where(AlertRule.destination_id == dest_id)
    )).all()
    for r in rules:
        logs = (await session.exec(select(AlertLog).where(AlertLog.rule_id == r.id))).all()
        for al in logs:
            await session.delete(al)
        await session.delete(r)
    await session.delete(dest)
    await session.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@router.get("/alerts/rules", response_model=list[RuleOut])
async def list_rules(
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    rules = (await session.exec(
        select(AlertRule)
        .where(AlertRule.user_id == current_user.id)
        .order_by(AlertRule.created_at)
    )).all()
    return [RuleOut(id=r.id, destination_id=r.destination_id, extension_id=r.extension_id,
                    event_type=r.event_type, enabled=r.enabled, created_at=r.created_at) for r in rules]


@router.post("/alerts/rules", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleIn,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    if body.event_type not in VALID_EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"event_type must be one of: {sorted(VALID_EVENT_TYPES)}")

    # Validate destination belongs to this user
    dest = await session.get(AlertDestination, body.destination_id)
    if not dest or dest.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Destination not found")

    # Validate extension belongs to this user (if provided)
    if body.extension_id is not None:
        ext = await session.get(Extension, body.extension_id)
        if not ext or ext.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Extension not found")

    rule = AlertRule(
        user_id=current_user.id,
        destination_id=body.destination_id,
        extension_id=body.extension_id,
        event_type=body.event_type,
        enabled=body.enabled,
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return RuleOut(id=rule.id, destination_id=rule.destination_id, extension_id=rule.extension_id,
                   event_type=rule.event_type, enabled=rule.enabled, created_at=rule.created_at)


@router.patch("/alerts/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: int,
    body: RulePatch,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    rule = await session.get(AlertRule, rule_id)
    if not rule or rule.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    if body.destination_id is not None:
        dest = await session.get(AlertDestination, body.destination_id)
        if not dest or dest.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Destination not found")
        rule.destination_id = body.destination_id
    if body.enabled is not None:
        rule.enabled = body.enabled
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return RuleOut(id=rule.id, destination_id=rule.destination_id, extension_id=rule.extension_id,
                   event_type=rule.event_type, enabled=rule.enabled, created_at=rule.created_at)


@router.delete("/alerts/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    rule = await session.get(AlertRule, rule_id)
    if not rule or rule.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    logs = (await session.exec(select(AlertLog).where(AlertLog.rule_id == rule_id))).all()
    for al in logs:
        await session.delete(al)
    await session.delete(rule)
    await session.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Alert log
# ---------------------------------------------------------------------------

@router.get("/alerts/log")
async def alert_log(
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
):
    rows = (await session.exec(
        select(AlertLog, AlertRule, AlertDestination, Extension)
        .join(AlertRule, AlertLog.rule_id == AlertRule.id)  # type: ignore[arg-type]
        .join(AlertDestination, AlertRule.destination_id == AlertDestination.id)  # type: ignore[arg-type]
        .join(Extension, AlertLog.extension_id == Extension.id)  # type: ignore[arg-type]
        .where(AlertRule.user_id == current_user.id)
        .order_by(AlertLog.sent_at.desc())
        .limit(limit)
    )).all()
    return [
        {
            "id": log.id,
            "sent_at": log.sent_at.isoformat(),
            "event_type": log.event_type,
            "extension_id": log.extension_id,
            "ext_name": ext.name or ext.extension_id,
            "dest_label": dest.label,
            "success": log.success,
            "error": log.error,
        }
        for log, rule, dest, ext in rows
    ]


# ---------------------------------------------------------------------------
# Test a webhook destination
# ---------------------------------------------------------------------------

@router.post("/alerts/destinations/{dest_id}/test")
async def test_destination(
    dest_id: int,
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    dest = await session.get(AlertDestination, dest_id)
    if not dest or dest.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    ext_payload: dict = {
        "id": 0,
        "name": "Example Extension",
        "store": "chrome",
        "store_url": "https://chromewebstore.google.com/detail/example",
    }
    if settings.app_base_url:
        ext_payload["marvin_url"] = f"{settings.app_base_url.rstrip('/')}/extensions/0"
    payload = {
        "event": "test",
        "extension": ext_payload,
        "change": {"old": "low", "new": "high"},
        "risk_score": 62,
    }
    client: httpx.AsyncClient = request.app.state.http_client
    try:
        resp = await client.post(dest.target, json=payload, timeout=10.0)
        resp.raise_for_status()
        return {"ok": True, "status_code": resp.status_code}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
