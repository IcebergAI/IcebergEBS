"""Admin JSON API for the outbound-proxy routing config (#216).

Settings CRUD on the singleton ProxySettings row plus an SSRF-safe connectivity
test. The test endpoint takes a *label* from a server-built egress-target map,
never a URL — an arbitrary-URL form would be an SSRF oracle for internal hosts
(e.g. 169.254.169.254). Failures return only the exception class name; the full
detail is logged server-side through ``proxy.scrub`` so the env-only proxy
credentials can never reach a caller or a log line (M4).
"""

import logging
from datetime import datetime
from typing import NamedTuple
from urllib.parse import urlparse, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import proxy, proxy_settings
from app.deps import AdminUser, SessionDep
from app.models import AlertDestination
from app.webhooks import _authority, validate_webhook_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["proxy"])

_TEST_TIMEOUT = 10.0


class _EgressTarget(NamedTuple):
    url: str
    # Webhook origins are user-controlled destinations: the probe must apply the
    # same SSRF discipline as delivery (validate + pin), unlike the fixed store set.
    is_webhook: bool = False


# The store origins every deployment talks to (see .claude/rules/fetchers.md).
_STORE_TARGETS: dict[str, _EgressTarget] = {
    "Chrome Web Store (detail pages)": _EgressTarget("https://chromewebstore.google.com"),
    "Chrome Web Store (CRX download)": _EgressTarget("https://clients2.google.com"),
    "Edge Add-ons (details API)": _EgressTarget("https://microsoftedge.microsoft.com"),
    "Edge Add-ons (CRX download)": _EgressTarget("https://edge.microsoft.com"),
    "VS Code Marketplace": _EgressTarget("https://marketplace.visualstudio.com"),
}


class ProxySettingsOut(BaseModel):
    # Never credentials: they are env-only and not on the row at all.
    model_config = ConfigDict(from_attributes=True)

    mode: str
    proxy_url: str
    no_proxy: str
    updated_at: datetime


class ProxySettingsUpdate(BaseModel):
    # extra="forbid": a PUT smuggling `username`/`proxy_password` keys is a 422,
    # not silently dropped — credentials are env-only by construction.
    model_config = ConfigDict(extra="forbid")

    mode: str | None = None
    proxy_url: str | None = None
    no_proxy: str | None = None

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, v: str | None) -> str | None:
        # Strict 422 on junk rather than deep_thought's silent SYSTEM coercion —
        # a typo in an admin PUT should surface, not silently change semantics.
        if v is None:
            return v
        try:
            return proxy.ProxyMode(v.strip().upper()).value
        except ValueError:
            raise ValueError(f"mode must be one of {', '.join(m.value for m in proxy.ProxyMode)}") from None

    @field_validator("proxy_url")
    @classmethod
    def _valid_proxy_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return ""
        parsed = urlsplit(v)
        if parsed.scheme not in proxy.PROXY_URL_SCHEMES or not parsed.hostname:
            raise ValueError(
                "proxy_url must be an absolute URL with scheme "
                f"{'|'.join(proxy.PROXY_URL_SCHEMES)} and a host (e.g. http://proxy.corp:3128)"
            )
        if parsed.username or parsed.password:
            # Credentials are env-only (ICEBERG_EBS_PROXY_USERNAME/_PASSWORD). A
            # userinfo URL would be persisted to the DB and echoed by every GET,
            # breaking that guarantee.
            raise ValueError(
                "proxy_url must not contain credentials — set ICEBERG_EBS_PROXY_USERNAME / "
                "ICEBERG_EBS_PROXY_PASSWORD in the environment instead"
            )
        return v


class ProxyTestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str


def _origin(url: str) -> str:
    """Reduce a URL to its origin (scheme://host[:port]/).

    Webhook URLs are capability URLs (the Slack-style path IS the secret): a
    connectivity test must check reachability of the host without exercising the
    capability or putting the token on the wire / in proxy logs.
    """
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


async def egress_targets(session: AsyncSession) -> dict[str, _EgressTarget]:
    """Label -> target map of everything this deployment dials out to.

    Server-built on purpose: the /test endpoint resolves a label through this
    map and never accepts a URL from the request body.
    """
    targets = dict(_STORE_TARGETS)
    result = await session.exec(
        select(AlertDestination).where(AlertDestination.enabled == True)  # noqa: E712
    )
    for dest in result.all():
        targets[f"Webhook: {dest.label} (#{dest.id})"] = _EgressTarget(_origin(dest.target), is_webhook=True)
    return targets


@router.get("/proxy/settings")
async def get_proxy_settings(_: AdminUser, session: SessionDep) -> ProxySettingsOut:
    row = await proxy_settings.get_settings(session)
    return ProxySettingsOut.model_validate(row)


@router.put("/proxy/settings")
async def put_proxy_settings(body: ProxySettingsUpdate, _: AdminUser, session: SessionDep) -> ProxySettingsOut:
    # The EXPLICIT⇒URL invariant is enforced inside update_settings, on the
    # RESULTING row under a FOR UPDATE lock — a route-level pre-check would be a
    # TOCTOU against a concurrent PUT (e.g. one request sets mode=EXPLICIT while
    # another clears proxy_url; each pre-check passes, the merge fails open).
    try:
        row = await proxy_settings.update_settings(session, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return ProxySettingsOut.model_validate(row)


@router.get("/proxy/targets")
async def get_proxy_targets(_: AdminUser, session: SessionDep) -> dict:
    return {"targets": sorted(await egress_targets(session))}


@router.post("/proxy/test")
async def test_proxy(body: ProxyTestIn, _: AdminUser, session: SessionDep) -> dict:
    """Dial one known egress target with the currently-saved routing config.

    Redirects are never followed: a probe only needs to prove reachability, and a
    user-controlled webhook origin could otherwise 3xx-bounce the admin's request
    to a private address. Webhook targets additionally get the full delivery-path
    SSRF treatment — validate + resolve + connect to the pinned public IP with the
    original hostname kept for Host/SNI — mirroring ``send_webhook``.
    """
    await proxy_settings.refresh_cache(session)
    row = await proxy_settings.get_settings(session)
    target = (await egress_targets(session)).get(body.target)
    if target is None:
        raise HTTPException(status_code=400, detail="Unknown target")
    cfg = proxy.ProxyConfig(mode=row.mode, proxy_url=row.proxy_url, no_proxy=row.no_proxy)
    # via_proxy reports the route of the ATTEMPTED request only: it stays False
    # until the routing decision for the URL actually dialled (for webhooks, the
    # pinned-IP form — what the routing transport sees in production) is computed.
    # A webhook that fails validation is never dialled, so no route is claimed.
    decision: str | None = None
    try:
        url = target.url
        headers: dict[str, str] = {}
        extensions: dict[str, str] = {}
        if target.is_webhook:
            pinned_ip = (await validate_webhook_url(url))[0]
            parsed = urlparse(url)
            host = parsed.hostname or ""
            url = parsed._replace(netloc=_authority(pinned_ip, parsed.port)).geturl()
            headers = {"Host": _authority(host, parsed.port)}
            if parsed.scheme == "https":
                extensions = {"sni_hostname": host}
        # Resolve through OUR parser even for SYSTEM mode (trust_env=False) so the
        # test exercises exactly the semantics ProxyRoutingTransport applies — not
        # httpx's own env handling, which the main client never uses. Fresh
        # throwaway client: a connectivity probe must not retry or share pools.
        decision = proxy.resolve_proxy_url(cfg, url)
        async with httpx.AsyncClient(
            timeout=_TEST_TIMEOUT, follow_redirects=False, trust_env=False, proxy=decision
        ) as client:
            resp = await client.get(url, headers=headers, extensions=extensions)
        result = f"ok: HTTP {resp.status_code}"
    except Exception as exc:
        # Class name only — the message can embed the credential-bearing proxy URL (M4).
        logger.warning("Proxy connectivity test for %r failed: %s", body.target, proxy.scrub(str(exc)))
        result = f"error: {type(exc).__name__}"
    return {"target": body.target, "via_proxy": decision is not None, "result": result}
