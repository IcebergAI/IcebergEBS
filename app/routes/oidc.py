"""OIDC / SSO routes (#32).

Authorization-Code + PKCE against a configured IdP. The login route redirects to
the provider; the callback validates the response (state/nonce/ID-token signature,
issuer, audience, expiry — all by Authlib), provisions/looks up the local user,
and then mints the *existing* local session cookie so every downstream authz
check is unchanged. Auth failures redirect to /login?error=sso with the detail
logged server-side — the authorization code / tokens are never logged.
"""

import logging

import httpx
from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import oidc_settings
from app.auth import set_oidc_id_token, set_session
from app.config import settings
from app.deps import SessionDep
from app.oidc import service as oidc_service
from app.oidc.base import get_adapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


def _callback_url(request: Request, provider: str) -> str:
    """Absolute redirect_uri the IdP will call back. Honours a configured base
    (for proxies that rewrite host/scheme) else derives it from the request."""
    # Prefer the SSO-specific base, then the shared public base URL used for
    # webhook deep links (app_base_url), then the request — so an operator behind a
    # host-rewriting proxy who already set ICEBERG_EBS_APP_BASE_URL gets a correct
    # callback without configuring the host twice.
    redirect_base = oidc_settings.get_config().oidc_redirect_base_url or settings.app_base_url
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
    # authorize_redirect fetches the discovery document; a down IdP/proxy raises an
    # httpx error (not OAuthError) — surface it as an SSO failure, never a raw 500.
    try:
        return await client.authorize_redirect(request, redirect_uri)
    except (OAuthError, httpx.HTTPError) as exc:
        logger.warning("OIDC login start failed: provider=%s (%s)", provider, type(exc).__name__)
        return RedirectResponse("/login?error=sso", status_code=303)


@router.get("/{provider}/callback", name="oidc_callback")
async def oidc_callback(provider: str, request: Request, session: SessionDep):
    oidc_service.ensure_registered()
    cfg = oidc_service.get_provider(provider)
    client = oidc_service.oauth.create_client(provider)
    adapter = get_adapter(provider)
    if cfg is None or client is None or adapter is None:
        raise HTTPException(status_code=404, detail="Unknown SSO provider")

    # Validate state/nonce, exchange the code, validate the ID token (signature
    # via JWKS, iss/aud/exp/iat/nonce). OAuthError is a validation failure; an
    # httpx error is the token endpoint / proxy being unreachable — both are auth
    # failures that redirect, never a raw 500. Never log the code or token.
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as exc:
        logger.warning("OIDC login failed: provider=%s id-token validation (%s)", provider, exc.error)
        return RedirectResponse("/login?error=sso", status_code=303)
    except httpx.HTTPError as exc:
        logger.warning("OIDC login failed: provider=%s token exchange unreachable (%s)", provider, type(exc).__name__)
        return RedirectResponse("/login?error=sso", status_code=303)

    # Fail CLOSED to the ID-token claims only. Authlib populates token["userinfo"]
    # exactly when it validated the ID token (signature + nonce); if it's absent
    # the ID token was missing/unvalidated, so we do NOT fall back to the userinfo
    # endpoint (those claims are not nonce-bound / ID-token-validated — logging in
    # from them silently downgrades OIDC to plain OAuth).
    claims = token.get("userinfo")
    if not claims:
        logger.warning("OIDC login failed: provider=%s no validated ID-token claims", provider)
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
    # the password_changed_at session-revocation cutoff — but with the shorter SSO
    # session lifetime (#221) so an IdP-side disable/reset propagates via forced
    # re-auth. The id_token is stashed (HttpOnly) as the RP-initiated-logout hint.
    response = RedirectResponse("/", status_code=303)
    set_session(response, user.username, max_age=settings.oidc_session_max_age)
    id_token = token.get("id_token")
    if id_token:
        set_oidc_id_token(response, id_token, max_age=settings.oidc_session_max_age)
    logger.info("OIDC login: user=%s provider=%s", user.username, provider)
    return response
