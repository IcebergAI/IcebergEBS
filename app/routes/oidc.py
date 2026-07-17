"""OIDC / SSO routes (#32).

Authorization-Code + PKCE against a configured IdP. The login route redirects to
the provider; the callback validates the response (state/nonce/ID-token signature,
issuer, audience, expiry — all by Authlib), provisions/looks up the local user,
and then mints the *existing* local session cookie so every downstream authz
check is unchanged. Auth failures redirect to /login?error=sso with the detail
logged server-side — the authorization code / tokens are never logged.
"""

import logging

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import oidc_settings
from app.auth import set_session
from app.deps import SessionDep
from app.oidc import service as oidc_service
from app.oidc.base import get_adapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


def _callback_url(request: Request, provider: str) -> str:
    """Absolute redirect_uri the IdP will call back. Honours a configured base
    (for proxies that rewrite host/scheme) else derives it from the request."""
    redirect_base = oidc_settings.get_config().oidc_redirect_base_url
    if redirect_base:
        return f"{redirect_base.rstrip('/')}/auth/oidc/{provider}/callback"
    return str(request.url_for("oidc_callback", provider=provider))


@router.get("/{provider}/login", name="oidc_login")
async def oidc_login(provider: str, request: Request):
    oidc_service.ensure_registered()
    cfg = oidc_service.get_provider(provider)
    client = oidc_service.oauth.create_client(provider)
    if cfg is None or client is None:
        raise HTTPException(status_code=404, detail="Unknown SSO provider")
    redirect_uri = _callback_url(request, provider)
    # Authlib generates + stores state (and, for openid scope, nonce) + the PKCE
    # verifier in request.session (the dedicated short-lived handshake cookie —
    # see SessionMiddleware in main.py); they're validated on callback.
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/{provider}/callback", name="oidc_callback")
async def oidc_callback(provider: str, request: Request, session: SessionDep):
    oidc_service.ensure_registered()
    cfg = oidc_service.get_provider(provider)
    client = oidc_service.oauth.create_client(provider)
    adapter = get_adapter(provider)
    if cfg is None or client is None or adapter is None:
        raise HTTPException(status_code=404, detail="Unknown SSO provider")

    # Validate state/nonce, exchange the code, validate the ID token (signature
    # via JWKS, iss/aud/exp/iat/nonce). Any failure here is an auth failure —
    # never log the code or token.
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as exc:
        logger.warning("OIDC login failed: provider=%s id-token validation (%s)", provider, exc.error)
        return RedirectResponse("/login?error=sso", status_code=303)

    claims = token.get("userinfo")
    if not claims:
        try:
            claims = await client.userinfo(token=token)
        except Exception:
            claims = None
    if not claims:
        logger.warning("OIDC login failed: provider=%s no id-token claims", provider)
        return RedirectResponse("/login?error=sso", status_code=303)

    try:
        identity = adapter.extract_identity(dict(claims), cfg.role_claim)
    except ValueError as exc:
        logger.warning("OIDC login failed: provider=%s %s", provider, exc)
        return RedirectResponse("/login?error=sso", status_code=303)

    try:
        user, _created = await oidc_service.provision_oidc_user(session, cfg=cfg, identity=identity)
    except oidc_service.OIDCProvisionError as exc:
        logger.warning("OIDC login denied: provider=%s %s", provider, exc.reason)
        return RedirectResponse("/login?error=sso", status_code=303)

    # Same cookie as the password flow — downstream auth is identical, including
    # the password_changed_at session-revocation cutoff.
    response = RedirectResponse("/", status_code=303)
    set_session(response, user.username)
    logger.info("OIDC login: user=%s provider=%s", user.username, provider)
    return response
