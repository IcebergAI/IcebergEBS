import json
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
from app.senders import AlertMessage, DestinationConfigError, get_sender, kind_descriptors, sender_kinds
from app.senders.webhook import extension_deep_link

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["alerts"])

VALID_EVENT_TYPES = {"risk_level_change", "publisher_change", "permission_change", "new_version"}


async def _validate_destination(kind: str, target: str, config: dict[str, str]) -> None:
    """Validate a destination against its kind's sender, translating failures to 422.

    Dispatches to the sender registry so each kind owns its own rules (URL SSRF for
    the HTTP kinds, recipient/config checks for email/ticketing), replacing the
    webhook-only check. An unknown kind is a 422 listing the valid kinds; a
    DestinationConfigError carries a static, user-facing message."""
    sender = get_sender(kind)
    if sender is None:
        raise HTTPException(status_code=422, detail=f"kind must be one of: {sorted(sender_kinds())}")
    available, reason = sender.availability()
    if not available:
        raise HTTPException(status_code=422, detail=reason or f"The '{kind}' destination kind is unavailable")
    try:
        await sender.validate(target, config)
    except DestinationConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DestinationOut(BaseModel):
    id: int
    label: str
    kind: str
    target: str
    config: dict[str, str]
    enabled: bool
    created_at: datetime

    @classmethod
    def from_db(cls, d: AlertDestination) -> "DestinationOut":
        # config is stored JSON-in-str; expose the parsed dict. Nothing in config is
        # secret (per-destination credentials are env-only refs), so no redaction.
        return cls(
            id=d.id,
            label=d.label,
            kind=d.kind,
            target=d.target,
            config=d.config_dict(),
            enabled=d.enabled,
            created_at=d.created_at,
        )


class DestinationIn(BaseModel):
    label: str
    kind: str = "webhook"  # backwards-compatible default for existing API callers
    target: str
    config: dict[str, str] = {}
    enabled: bool = True


class DestinationPatch(BaseModel):
    label: str | None = None
    kind: str | None = None
    target: str | None = None
    config: dict[str, str] | None = None
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


@router.get("/alerts/destination-kinds")
async def destination_kinds(current_user: CurrentUser) -> list[dict]:
    """Descriptors for every delivery kind (label, target label, config fields,
    availability) — drives the dynamic destination form and lets API/SOAR consumers
    discover kinds. Auth-gated but user-independent."""
    return kind_descriptors()


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
    return [DestinationOut.from_db(d) for d in dests]


@router.post("/alerts/destinations", status_code=201)
async def create_destination(
    body: DestinationIn,
    current_user: CurrentUser,
    session: SessionDep,
) -> DestinationOut:
    await _validate_destination(body.kind, body.target, body.config)
    dest = AlertDestination(
        user_id=current_user.id,
        label=body.label,
        kind=body.kind,
        target=body.target,
        config=json.dumps(body.config),
        enabled=body.enabled,
    )
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.from_db(dest)


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
    # Validate the RESULTING kind/target/config, not just the changed fields (the
    # #217 TOCTOU discipline): changing the kind alone must revalidate the existing
    # target+config under the new adapter, and vice-versa.
    result_kind = body.kind if body.kind is not None else dest.kind
    result_target = body.target if body.target is not None else dest.target
    result_config = body.config if body.config is not None else dest.config_dict()
    if body.kind is not None or body.target is not None or body.config is not None:
        await _validate_destination(result_kind, result_target, result_config)
        dest.kind = result_kind
        dest.target = result_target
        dest.config = json.dumps(result_config)
    if body.enabled is not None:
        dest.enabled = body.enabled
    session.add(dest)
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.from_db(dest)


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
    # Dispatched through the same sender.send() real alerts use, so a test IS the real
    # delivery path for every kind (#168 generalised). For a Jira/ServiceNow
    # destination this deliberately creates one real test ticket — that is what proves
    # project key, auth and field mapping end-to-end (documented on the help page).
    sender = get_sender(dest.kind)
    if sender is None:
        raise HTTPException(status_code=422, detail=f"Unknown destination kind '{dest.kind}'")
    message = AlertMessage(
        text=f'IcebergEBS test alert from destination "{dest.label}"',
        event="test",
        ext_id=0,
        name="Example Extension",
        store="chrome",
        store_url="https://chromewebstore.google.com/detail/example",
        old="low",
        new="high",
        risk_score=62,
        app_url=extension_deep_link(0),
    )
    client: httpx.AsyncClient = request.app.state.http_client
    try:
        await sender.send(client, dest.target, dest.config_dict(), message)
        return {"ok": True}
    except Exception as exc:
        # Never surface the raw exception text to the caller: it can contain the
        # resolved IP, internal hostnames, or other SSRF-probing detail. Log the
        # full error server-side and return a generic message (M4 / #9).
        # Scrub too (#228): delivery through the outbound proxy can echo the
        # credential-injected proxy URL in the exception text.
        logger.warning("Test delivery to destination %d failed: %s", dest_id, proxy.scrub(str(exc)))
        raise HTTPException(
            status_code=502,
            detail="Failed to deliver the test notification to the destination",
        ) from exc
