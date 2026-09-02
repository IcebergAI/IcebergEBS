import json
import logging
from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlmodel import select

from app import audit, proxy
from app.alert_queries import get_alert_log
from app.deps import AdminUser, CurrentUser, SessionDep, get_owned_or_404
from app.models import AlertDestination, AlertRule, Extension
from app.senders import AlertMessage, DestinationConfigError, get_sender, kind_descriptors, sender_kinds
from app.senders.webhook import extension_deep_link

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["alerts"])

VALID_EVENT_TYPES = {
    "risk_level_change",
    "publisher_change",
    "permission_change",
    "new_version",
    "capability_change",
    "threat_match",
}


def _audit_target(target: str) -> str:
    """The trail's view of a destination target: the ORIGIN only for URL targets.

    A Slack/Teams incoming-webhook URL is a capability token — the path IS the
    credential — and Jira/ServiceNow base URLs name internal hosts. The audit log is
    readable by auditors and retained forever, so it records where alerts go
    (scheme + host [+ port]) and never the path, query, or **userinfo**: built from
    ``hostname``/``port``, not ``netloc``, because netloc keeps a ``user:pass@``
    prefix (review finding on #353). Non-URL targets (email recipients) are not
    credentials and are kept as-is (#34).
    """
    parts = urlsplit(target.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return target
    host = parts.hostname
    if ":" in host:  # IPv6 literal — hostname strips the brackets; put them back
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:  # non-numeric port: don't echo the junk, keep the host only
        port = None
    return f"{parts.scheme}://{host}" if port is None else f"{parts.scheme}://{host}:{port}"


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
    request: Request,
    current_user: AdminUser,
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
    await session.flush()
    # Origin only — a webhook URL's path is a capability token (see _audit_target);
    # config values are field-name-only (#34).
    audit.record(
        session,
        current_user,
        "destination.create",
        "destination",
        dest.id,
        {
            "label": body.label,
            "kind": body.kind,
            "target": _audit_target(body.target),
            "config_fields": sorted(body.config),
        },
        request=request,
    )
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.from_db(dest)


@router.patch("/alerts/destinations/{dest_id}")
async def update_destination(
    dest_id: int,
    body: DestinationPatch,
    request: Request,
    current_user: AdminUser,
    session: SessionDep,
) -> DestinationOut:
    # Row-lock + refresh (#217): the resulting-state validation below reads the
    # persisted kind/target/config, so a concurrent partial PATCH must be serialized —
    # otherwise one request could commit kind=email while a stale request updates only
    # `target`, leaving an email destination with a webhook-URL target that no request
    # ever validated together (bot review). FOR UPDATE holds until this txn commits.
    dest = await get_owned_or_404(session, AlertDestination, dest_id, current_user.id, for_update=True)
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
    audit.record(
        session,
        current_user,
        "destination.update",
        "destination",
        dest_id,
        {
            "fields": sorted(body.model_fields_set),
            "label": dest.label,
            "kind": dest.kind,
            "target": _audit_target(dest.target),
            "enabled": dest.enabled,
        },
        request=request,
    )
    await session.commit()
    await session.refresh(dest)
    return DestinationOut.from_db(dest)


@router.delete("/alerts/destinations/{dest_id}")
async def delete_destination(
    dest_id: int,
    request: Request,
    current_user: AdminUser,
    session: SessionDep,
):
    dest = await get_owned_or_404(session, AlertDestination, dest_id, current_user.id)
    audit.record(
        session,
        current_user,
        "destination.delete",
        "destination",
        dest_id,
        {"label": dest.label, "kind": dest.kind, "target": _audit_target(dest.target)},
        request=request,
    )
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
    request: Request,
    current_user: AdminUser,
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
    await session.flush()
    audit.record(
        session,
        current_user,
        "rule.create",
        "rule",
        rule.id,
        {
            "destination_id": body.destination_id,
            "extension_id": body.extension_id,
            "event_type": body.event_type,
            "enabled": body.enabled,
        },
        request=request,
    )
    await session.commit()
    await session.refresh(rule)
    return RuleOut.model_validate(rule)


@router.patch("/alerts/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    body: RulePatch,
    request: Request,
    current_user: AdminUser,
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
    audit.record(
        session,
        current_user,
        "rule.update",
        "rule",
        rule_id,
        {"fields": sorted(body.model_fields_set), "destination_id": rule.destination_id, "enabled": rule.enabled},
        request=request,
    )
    await session.commit()
    await session.refresh(rule)
    return RuleOut.model_validate(rule)


@router.delete("/alerts/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    request: Request,
    current_user: AdminUser,
    session: SessionDep,
):
    rule = await get_owned_or_404(session, AlertRule, rule_id, current_user.id)
    audit.record(
        session,
        current_user,
        "rule.delete",
        "rule",
        rule_id,
        {"destination_id": rule.destination_id, "extension_id": rule.extension_id, "event_type": rule.event_type},
        request=request,
    )
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
    current_user: AdminUser,
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
    target, config = dest.target, dest.config_dict()  # read before the commit below expires `dest`
    # An outbound send is an action with external effect (a Jira/ServiceNow test
    # creates a real ticket), so the trail records the ATTEMPT durably before the
    # wire is touched — the row must exist even if delivery hangs or fails (#34).
    audit.record(
        session,
        current_user,
        "destination.test",
        "destination",
        dest_id,
        {"label": dest.label, "kind": dest.kind},
        request=request,
    )
    await session.commit()
    try:
        await sender.send(client, target, config, message)
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
