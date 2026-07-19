import logging
from datetime import datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlmodel import select

from app import proxy
from app.alert_queries import get_alert_log
from app.deps import CurrentUser, SessionDep, get_owned_or_404
from app.models import AlertDestination, AlertRule, Extension
from app.notifications import build_alert_payload
from app.webhooks import WebhookValidationError, send_webhook, validate_webhook_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["alerts"])

VALID_EVENT_TYPES = {"risk_level_change", "publisher_change", "permission_change", "new_version"}


async def _validate_webhook_url(url: str) -> None:
    """Validate a destination webhook URL, translating failures to HTTP 422."""
    try:
        await validate_webhook_url(url)
    except WebhookValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DestinationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
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
    model_config = ConfigDict(from_attributes=True)
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


@router.get("/alerts/destinations")
async def list_destinations(
    current_user: CurrentUser,
    session: SessionDep,
) -> list[DestinationOut]:
    dests = (
        await session.exec(
            select(AlertDestination)
            .where(AlertDestination.user_id == current_user.id)
            .order_by(AlertDestination.created_at)
        )
    ).all()
    return [DestinationOut.model_validate(d) for d in dests]


@router.post("/alerts/destinations", status_code=201)
async def create_destination(
    body: DestinationIn,
    current_user: CurrentUser,
    session: SessionDep,
) -> DestinationOut:
    await _validate_webhook_url(body.target)
    dest = AlertDestination(
        user_id=current_user.id,
        label=body.label,
        target=body.target,
        enabled=body.enabled,
    )
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.model_validate(dest)


@router.patch("/alerts/destinations/{dest_id}")
async def update_destination(
    dest_id: int,
    body: DestinationPatch,
    current_user: CurrentUser,
    session: SessionDep,
) -> DestinationOut:
    dest = await get_owned_or_404(session, AlertDestination, dest_id, current_user.id)
    if body.label is not None:
        dest.label = body.label
    if body.target is not None:
        await _validate_webhook_url(body.target)
        dest.target = body.target
    if body.enabled is not None:
        dest.enabled = body.enabled
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.model_validate(dest)


@router.delete("/alerts/destinations/{dest_id}")
async def delete_destination(
    dest_id: int,
    current_user: CurrentUser,
    session: SessionDep,
):
    dest = await get_owned_or_404(session, AlertDestination, dest_id, current_user.id)
    # The FK ON DELETE actions handle the cleanup: the destination's rules cascade
    # away, and the AlertLog history rows pointing at this destination (and at those
    # rules) keep their user_id but have destination_id/rule_id set to NULL — so they
    # stay visible in the alert history rendered with a "—" destination.
    await session.delete(dest)
    await session.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.get("/alerts/rules")
async def list_rules(
    current_user: CurrentUser,
    session: SessionDep,
) -> list[RuleOut]:
    rules = (
        await session.exec(select(AlertRule).where(AlertRule.user_id == current_user.id).order_by(AlertRule.created_at))
    ).all()
    return [RuleOut.model_validate(r) for r in rules]


@router.post("/alerts/rules", status_code=201)
async def create_rule(
    body: RuleIn,
    current_user: CurrentUser,
    session: SessionDep,
) -> RuleOut:
    if body.event_type not in VALID_EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"event_type must be one of: {sorted(VALID_EVENT_TYPES)}")

    # Validate destination belongs to this user
    await get_owned_or_404(
        session, AlertDestination, body.destination_id, current_user.id, detail="Destination not found"
    )

    # Validate extension belongs to this user (if provided)
    if body.extension_id is not None:
        await get_owned_or_404(session, Extension, body.extension_id, current_user.id, detail="Extension not found")

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
    return RuleOut.model_validate(rule)


@router.patch("/alerts/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    body: RulePatch,
    current_user: CurrentUser,
    session: SessionDep,
) -> RuleOut:
    rule = await get_owned_or_404(session, AlertRule, rule_id, current_user.id)
    if body.destination_id is not None:
        await get_owned_or_404(
            session, AlertDestination, body.destination_id, current_user.id, detail="Destination not found"
        )
        rule.destination_id = body.destination_id
    if body.enabled is not None:
        rule.enabled = body.enabled
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return RuleOut.model_validate(rule)


@router.delete("/alerts/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    current_user: CurrentUser,
    session: SessionDep,
):
    rule = await get_owned_or_404(session, AlertRule, rule_id, current_user.id)
    # AlertLog.rule_id is ON DELETE SET NULL, so the history rows survive the rule.
    await session.delete(rule)
    await session.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Alert log
# ---------------------------------------------------------------------------


@router.get("/alerts/log")
async def alert_log(
    current_user: CurrentUser,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
):
    return await get_alert_log(current_user.id, session, limit)


# ---------------------------------------------------------------------------
# Test a webhook destination
# ---------------------------------------------------------------------------


@router.post("/alerts/destinations/{dest_id}/test")
async def test_destination(
    dest_id: int,
    request: Request,
    current_user: CurrentUser,
    session: SessionDep,
):
    dest = await get_owned_or_404(session, AlertDestination, dest_id, current_user.id)
    # Built through the shared builder so the test webhook is byte-for-byte the same
    # shape real alerts send — it can't silently drift as the payload evolves (#168).
    payload = build_alert_payload(
        text=f'IcebergEBS test alert from destination "{dest.label}"',
        event="test",
        ext_id=0,
        name="Example Extension",
        store="chrome",
        store_url="https://chromewebstore.google.com/detail/example",
        old="low",
        new="high",
        risk_score=62,
    )
    client: httpx.AsyncClient = request.app.state.http_client
    try:
        resp = await send_webhook(client, dest.target, payload)
        resp.raise_for_status()
        return {"ok": True, "status_code": resp.status_code}
    except Exception as exc:
        # Never surface the raw exception text to the caller: it can contain the
        # resolved IP, internal hostnames, or other SSRF-probing detail. Log the
        # full error server-side and return a generic message (M4 / #9).
        # Scrub too (#228): delivery through the outbound proxy can echo the
        # credential-injected proxy URL in the exception text.
        logger.warning("Webhook test to destination %d failed: %s", dest_id, proxy.scrub(str(exc)))
        raise HTTPException(
            status_code=502,
            detail="Failed to deliver test webhook to the destination",
        ) from exc
