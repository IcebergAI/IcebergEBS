import ipaddress
import logging
from datetime import datetime
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_auth
from app.config import settings
from app.database import get_session
from app.models import AlertDestination, AlertLog, AlertRule, Extension, User

logger = logging.getLogger(__name__)

router = APIRouter()

VALID_EVENT_TYPES = {"risk_level_change", "publisher_change", "permission_change", "new_version"}

_BLOCKED_HOSTNAMES = frozenset({"localhost", "localtest.me"})


def _validate_webhook_url(url: str) -> None:
    """Reject URLs that could be used for SSRF against internal services."""
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid webhook URL")

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="Webhook URL must use http or https")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HTTPException(status_code=422, detail="Webhook URL has no hostname")

    if hostname in _BLOCKED_HOSTNAMES:
        raise HTTPException(status_code=422, detail="Webhook URL hostname is not allowed")

    try:
        addr = ipaddress.ip_address(hostname)
        if not addr.is_global:
            raise HTTPException(
                status_code=422,
                detail="Webhook URL must not point to a private or reserved address",
            )
    except ValueError:
        pass  # Not a bare IP — hostname is fine


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
    _validate_webhook_url(body.target)
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
        _validate_webhook_url(body.target)
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
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
):
    # Fetch the user's rules first so we can look up labels without a
    # four-way JOIN that silently drops rows when an extension is deleted.
    rules = (await session.exec(
        select(AlertRule).where(AlertRule.user_id == current_user.id)
    )).all()
    if not rules:
        return []

    rule_ids = [r.id for r in rules]
    rule_map = {r.id: r for r in rules}

    dest_ids = list({r.destination_id for r in rules})
    dests = (await session.exec(
        select(AlertDestination).where(AlertDestination.id.in_(dest_ids))
    )).all()
    dest_map = {d.id: d for d in dests}

    logs = (await session.exec(
        select(AlertLog)
        .where(AlertLog.rule_id.in_(rule_ids))
        .order_by(AlertLog.sent_at.desc())
        .limit(limit)
    )).all()
    if not logs:
        return []

    ext_ids = list({log.extension_id for log in logs})
    exts = (await session.exec(
        select(Extension).where(Extension.id.in_(ext_ids))
    )).all()
    ext_map = {e.id: e for e in exts}

    result = []
    for log in logs:
        rule = rule_map.get(log.rule_id)
        dest = dest_map.get(rule.destination_id) if rule else None
        ext = ext_map.get(log.extension_id)
        result.append({
            "id": log.id,
            "sent_at": log.sent_at.isoformat(),
            "event_type": log.event_type,
            "extension_id": log.extension_id,
            "ext_name": (ext.name or ext.extension_id) if ext else f"Extension {log.extension_id}",
            "dest_label": dest.label if dest else "—",
            "success": log.success,
            "error": log.error,
        })
    return result


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
        "text": f"Marvin test alert from destination \"{dest.label}\"",
        "event": "test",
        "extension": ext_payload,
        "change": {"old": "low", "new": "high"},
        "risk_score": 62,
    }
    client: httpx.AsyncClient = request.app.state.http_client
    try:
        resp = await client.post(dest.target, json=payload, timeout=10.0, follow_redirects=False)
        resp.raise_for_status()
        return {"ok": True, "status_code": resp.status_code}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
