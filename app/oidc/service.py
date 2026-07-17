"""OIDC flow wiring + user provisioning (#32).

Holds the process-wide Authlib ``OAuth`` registry (built from the enabled provider
configs) and implements the match/JIT-provision policy that turns a validated
``OIDCIdentity`` into a local ``User``. Everything downstream is unchanged: the
callback mints the same session cookie the password flow mints
(``auth.set_session``), keyed on the user's username.
"""

from __future__ import annotations

import hashlib
import logging

import httpx
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.exc import IntegrityError
from sqlmodel import func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.fetchers.transport import ProxyRoutingTransport, RetryTransport
from app.models import User, _utcnow
from app.oidc import auth0 as _auth0  # noqa: F401 - registers adapter
from app.oidc import authentik as _authentik  # noqa: F401 - registers adapter
from app.oidc import entra as _entra  # noqa: F401 - registers adapter
from app.oidc import okta as _okta  # noqa: F401 - registers adapter
from app.oidc.base import OIDCIdentity
from app.oidc.config import OIDCProviderConfig

logger = logging.getLogger(__name__)

# Process-wide registry, populated by register_providers() (lifespan startup, or
# lazily via ensure_registered()).
oauth = OAuth()
_registered: dict[str, OIDCProviderConfig] = {}
_registration_done = False


class OIDCProvisionError(Exception):
    """A provisioning decision that denies login (collision, identity conflict)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _NonClosingTransport(httpx.AsyncBaseTransport):
    """Shield the shared transport chain from Authlib's per-call client lifecycle.

    Authlib opens a throwaway ``AsyncOAuth2Client`` per discovery/token/userinfo
    call (``async with self._get_oauth_client()``); closing that client would
    ``aclose()`` whatever transport it was given, killing the shared
    proxy-routing chain after the first callback. The real chain is closed once,
    in ``aclose_transport()`` at lifespan shutdown.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        return None


_transport_chain: httpx.AsyncBaseTransport | None = None


def _shared_transport() -> httpx.AsyncBaseTransport:
    """The OIDC egress transport: retry over proxy-routing, like all other egress.

    All IdP traffic (discovery, JWKS, token, userinfo) must obey the #216 outbound
    proxy config; ProxyRoutingTransport consults the live snapshot per request, so
    an admin proxy edit applies to the next OIDC request with no re-registration.
    """
    global _transport_chain
    if _transport_chain is None:
        limits = httpx.Limits(
            max_connections=settings.httpx_max_connections,
            max_keepalive_connections=settings.httpx_max_keepalive_connections,
        )
        _transport_chain = RetryTransport(
            ProxyRoutingTransport(limits=limits),
            max_retries=settings.httpx_max_retries,
            backoff_base=settings.httpx_backoff_base,
            backoff_cap=settings.httpx_backoff_cap,
        )
    return _NonClosingTransport(_transport_chain)


async def aclose_transport() -> None:
    """Close the shared OIDC transport chain (lifespan shutdown)."""
    global _transport_chain
    if _transport_chain is not None:
        await _transport_chain.aclose()
        _transport_chain = None


def register_providers() -> list[OIDCProviderConfig]:
    """Register every enabled provider with Authlib. Idempotent per process.

    Returns the registered provider configs (also used for the login-page buttons).
    """
    global _registration_done
    from app import oidc_settings

    configs = oidc_settings.get_config().enabled_providers()
    for cfg in configs:
        if cfg.key in _registered:
            continue
        # Authlib forwards the httpx.AsyncClient kwargs in client_kwargs (incl.
        # transport/timeout) to the AsyncOAuth2Client it builds per call, so the
        # shared proxy-routing transport covers discovery/JWKS/token/userinfo.
        oauth.register(
            name=cfg.key,
            client_id=cfg.client_id,
            client_secret=cfg.client_secret,
            server_metadata_url=cfg.metadata_url,
            client_kwargs={
                "scope": cfg.scopes,
                "code_challenge_method": "S256",  # force PKCE
                "timeout": settings.httpx_timeout,
                "transport": _shared_transport(),
            },
        )
        _registered[cfg.key] = cfg
    _registration_done = True
    return configs


def reset_registration() -> None:
    """Force providers to re-register on next use (after a settings change).

    Authlib's ``register()`` overwrites its ``_registry`` entry but
    ``create_client()`` returns the **cached** ``_clients[name]``, so
    re-registering alone would silently keep serving the old client — with the
    old client id/secret/metadata URL. Rebinding ``oauth`` to a fresh registry
    sidesteps Authlib's internals entirely; the routes reach it as
    ``oidc_service.oauth``, so they pick up the new object.
    """
    global oauth, _registration_done
    oauth = OAuth()
    _registered.clear()
    _registration_done = False


def ensure_registered() -> None:
    """Register providers once, lazily. Safe to call on every request — this is
    what makes the routes work whether or not the lifespan startup ran (e.g.
    under the test transport)."""
    if not _registration_done:
        register_providers()


def registered_providers() -> list[OIDCProviderConfig]:
    """Configs registered this process, in a stable order (for the login buttons)."""
    return list(_registered.values())


def get_provider(key: str) -> OIDCProviderConfig | None:
    return _registered.get(key)


def map_is_admin(cfg: OIDCProviderConfig, identity: OIDCIdentity) -> bool:
    """True iff any IdP group maps to "admin" in the provider's allowlist.

    Default is non-admin (no self-elevation). Any-match rather than
    deep_thought's first-match: the IdP does not guarantee group order, and for a
    boolean the deterministic union is the only sane semantics. Widens to a role
    enum when RBAC lands (#33).
    """
    return any(cfg.role_map.get(group) == "admin" for group in identity.groups)


def _derive_username(email: str, cfg: OIDCProviderConfig, identity: OIDCIdentity) -> str:
    """Deterministic fallback username when the email is taken as a username.

    Only reachable when a *different* account's username equals this identity's
    email (email collisions are denied outright before this). Suffix with a hash
    of the immutable (provider, subject) pair so retries resolve to the same name.
    """
    suffix = hashlib.sha256(f"{cfg.key}:{identity.subject}".encode()).hexdigest()[:8]
    return f"{email[:140]}-{suffix}"


async def _sync_returning_user(
    session: AsyncSession,
    *,
    cfg: OIDCProviderConfig,
    identity: OIDCIdentity,
    user: User,
) -> None:
    """Validate immutable identity provenance and synchronize an IdP-managed flag."""
    dirty = False
    if user.auth_tenant is not None and user.auth_tenant != identity.tenant_id:
        # Same (provider, subject) from a different tenant is a different
        # principal (or a misconfigured multi-tenant app) — never the same account.
        raise OIDCProvisionError("identity conflict")
    if user.auth_tenant is None and identity.tenant_id is not None:
        # Lazy provenance backfill for an identity created before auth_tenant
        # data was available. The provider/subject match was already validated.
        user.auth_tenant = identity.tenant_id
        dirty = True

    if user.role_managed_by_idp:
        mapped = map_is_admin(cfg, identity)
        if mapped != user.is_admin:
            previous = user.is_admin
            user.is_admin = mapped
            # Revoke sessions minted under the previous authorization state
            # (password_changed_at is the generic session cutoff — see models.User).
            # The callback issues this login a fresh cookie after commit.
            user.password_changed_at = _utcnow()
            dirty = True
            logger.warning(
                "OIDC admin sync for user %s via %s: is_admin %s -> %s",
                user.username,
                cfg.key,
                previous,
                mapped,
            )

    if dirty:
        session.add(user)
        await session.commit()
        await session.refresh(user)


async def provision_oidc_user(
    session: AsyncSession, *, cfg: OIDCProviderConfig, identity: OIDCIdentity
) -> tuple[User, bool]:
    """Resolve or create the local User for a validated OIDC identity.

    Returns ``(user, created)``. Raises OIDCProvisionError for identity conflicts
    and email collisions that require an explicit link flow.

    Match order:
      1. (auth_provider, stable subject) — returning OIDC user; validate tenant
         provenance and synchronize the IdP-managed admin flag.
      2. any email collision → deny; mutable human-readable claims never link
         (an IdP email claim must not be able to claim a local admin account).
      3. otherwise JIT-create an identity bound to the stable provider subject.
         The username is the normalized email (sessions are username-keyed); a
         residual username collision gets a deterministic hash suffix.
    """
    # 1. Returning OIDC identity. The row lock serialises concurrent callbacks
    # for the same subject so the admin-flag sync can't interleave.
    existing = (
        await session.exec(
            select(User).where(User.auth_provider == cfg.key, User.oidc_subject == identity.subject).with_for_update()
        )
    ).first()
    if existing is not None:
        await _sync_returning_user(session, cfg=cfg, identity=identity, user=existing)
        return existing, False

    # 2. Email is a mutable display/contact attribute, never an identity key.
    normalized_email = identity.email.strip().lower()
    by_email = (await session.exec(select(User).where(func.lower(User.email) == normalized_email))).first()
    if by_email is not None:
        raise OIDCProvisionError("account linking required")

    # 3. JIT create. The stable provider subject authenticates this account; the
    # email cannot claim an existing row because every collision above is denied.
    username = normalized_email
    username_taken = (await session.exec(select(User).where(User.username == username))).first()
    if username_taken is not None:
        # A local account whose username happens to be this email (with a
        # different/absent email of its own — same-email rows were denied above).
        username = _derive_username(normalized_email, cfg, identity)
    user = User(
        username=username,
        password_hash=None,
        email=normalized_email,
        is_admin=map_is_admin(cfg, identity),
        auth_provider=cfg.key,
        oidc_subject=identity.subject,
        auth_tenant=identity.tenant_id,
        role_managed_by_idp=True,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        # A unique race: either a concurrent callback JIT-created this same
        # (provider, subject), or the derived username was taken in the gap.
        await session.rollback()
        existing = (
            await session.exec(
                select(User)
                .where(User.auth_provider == cfg.key, User.oidc_subject == identity.subject)
                .with_for_update()
            )
        ).first()
        if existing is not None:
            await _sync_returning_user(session, cfg=cfg, identity=identity, user=existing)
            return existing, False
        logger.warning("OIDC JIT provisioning conflict for provider %s", cfg.key)
        raise OIDCProvisionError("provisioning conflict") from None
    await session.refresh(user)
    logger.info("OIDC JIT-provisioned user %s via %s (admin=%s)", user.username, cfg.key, user.is_admin)
    return user, True
