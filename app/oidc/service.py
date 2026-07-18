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
from app.fetchers.transport import build_egress_transport
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
        # Same factory as the main HTTP client (#231) — one egress recipe, so a
        # retry/limits change can't drift between the two, and OIDC egress is pinned
        # to the proxy-routing chain by construction (#216).
        _transport_chain = build_egress_transport(settings)
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


def _subject_hash(identity: OIDCIdentity) -> str:
    """Full hex digest of the immutable (issuer, subject) identity."""
    return hashlib.sha256(f"{identity.issuer}:{identity.subject}".encode()).hexdigest()


def _derive_username(email: str, identity: OIDCIdentity, width: int = 8) -> str:
    """Deterministic fallback username when the email is taken as a username.

    Only reachable when a *different* account's username equals this identity's
    email (email collisions are denied outright before this). Suffix with a hash
    of the immutable (issuer, subject) pair so retries resolve to the same name;
    ``width`` widens the suffix if even the derived name is already taken, so a
    pre-existing squatter of the derived name can't permanently dead-end the login.
    """
    return f"{email[:140]}-{_subject_hash(identity)[:width]}"


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

    await _sync_email(session, identity=identity, user=user)


async def _sync_email(session: AsyncSession, *, identity: OIDCIdentity, user: User) -> None:
    """Refresh a returning SSO account's email from the verified claim (#233).

    Kept a separate best-effort commit from the tenant/admin sync so an email that
    collides with another SSO account can't undo the admin sync or break the login.
    Without this, an account's email is frozen at first-login: if the IdP later
    reassigns that address to a new person, their first login is permanently denied
    ("account linking required") by the stale row, with no admin remediation path.

    Only a **verified** email is adopted — an unverified claim is untrustworthy (same
    rule as JIT provisioning). A collision with another SSO row (the partial unique
    index ``uq_user_sso_email``) leaves the stale address in place rather than failing
    the login or silently stealing the address; a genuine duplicate needs an admin.
    """
    if not identity.email_verified:
        return
    new_email = (identity.email or "").strip().lower()
    if not new_email or new_email == user.email:
        return
    user.email = new_email
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        await session.refresh(user)  # discard the rejected in-memory change
        logger.warning(
            "OIDC email sync skipped for %s via %s: address already owned by another SSO account",
            user.username,
            user.auth_provider,
        )
        return
    await session.refresh(user)


async def _match_identity(session: AsyncSession, identity: OIDCIdentity, *, provider: str, lock: bool) -> User | None:
    """Look up the account for a validated (issuer, subject) **within one provider**.

    Scoping the match to ``auth_provider == provider`` is the #226 fix: Authlib only
    validates the token's ``iss`` against *this* provider's own discovery metadata, so
    a hostile/compromised configured provider can publish another provider's issuer,
    serve its own JWKS, and mint a token carrying that trust domain's (iss, sub). An
    unscoped match would resolve such a token to the other provider's account (a
    cross-provider takeover). The issuer stays in the key (a re-pointed adapter still
    changes it — the #218 protection), and the account row records the provider it was
    provisioned through, so a spoofed token from a different provider never matches.
    """
    stmt = select(User).where(
        User.auth_provider == provider,
        User.oidc_issuer == identity.issuer,
        User.oidc_subject == identity.subject,
    )
    if lock:
        stmt = stmt.with_for_update()
    return (await session.exec(stmt)).first()


async def _foreign_identity_exists(session: AsyncSession, identity: OIDCIdentity, *, provider: str) -> bool:
    """True if this (issuer, subject) is already owned by a **different** provider.

    A (issuer, subject) is globally unique (``uq_user_issuer_subject``) and owned by the
    first provider to claim it. Because the issuer claim can be spoofed by another
    configured provider (see ``_match_identity``), a second provider presenting the same
    pair is refused as an identity conflict rather than inheriting or shadowing the row.
    """
    stmt = select(User).where(
        User.oidc_issuer == identity.issuer,
        User.oidc_subject == identity.subject,
        User.auth_provider != provider,
    )
    return (await session.exec(stmt)).first() is not None


async def _email_owner(session: AsyncSession, normalized_email: str) -> User | None:
    return (await session.exec(select(User).where(func.lower(User.email) == normalized_email))).first()


async def provision_oidc_user(
    session: AsyncSession, *, cfg: OIDCProviderConfig, identity: OIDCIdentity
) -> tuple[User, bool]:
    """Resolve or create the local User for a validated OIDC identity.

    Returns ``(user, created)``. Raises OIDCProvisionError for identity conflicts
    and email collisions that require an explicit link flow.

    Match order:
      1. (auth_provider, oidc_issuer, subject) — returning OIDC user; validate tenant
         provenance, synchronize the IdP-managed admin flag, and refresh the verified
         email (#233 — a stale address would otherwise block another user's JIT forever).
         The match is scoped to the configured provider so a hostile provider spoofing
         another's issuer can't inherit the account (#226); the issuer stays in the key
         so a re-pointed adapter can't either (#218).
      1b. the same (issuer, subject) owned by a DIFFERENT provider → deny ("identity
         conflict"); the issuer claim alone can't distinguish trust domains, so a second
         provider presenting it is refused rather than allowed to create/shadow a row.
      2. new identity with an UNVERIFIED email → deny; the account's username and
         email are derived from the email claim, so provisioning on an unverified
         claim would let a user squat an arbitrary address (locking out its real
         owner on their first login, and mislabelling the squatter in admin views).
      3. any email collision → deny; mutable human-readable claims never link
         (an IdP email claim must not be able to claim a local admin account).
      4. otherwise JIT-create an identity bound to the stable (issuer, subject).
         The username is the normalized email (sessions are username-keyed); a
         residual username collision gets a deterministic hash suffix.
    """
    # 1. Returning OIDC identity. The row lock serialises concurrent callbacks for
    # the same identity so the admin-flag sync can't interleave. Verification is not
    # re-checked here: identity is already established by (issuer, subject).
    existing = await _match_identity(session, identity, provider=cfg.key, lock=True)
    if existing is not None:
        await _sync_returning_user(session, cfg=cfg, identity=identity, user=existing)
        return existing, False

    # 1b. The (issuer, subject) is owned by another configured provider. Authlib only
    # checks iss against THIS provider's discovery metadata, so the issuer claim can't
    # distinguish trust domains — refuse rather than let a hostile provider create a
    # shadow row or (via the global unique constraint) dead-end in a confusing conflict.
    if await _foreign_identity_exists(session, identity, provider=cfg.key):
        raise OIDCProvisionError("identity conflict")

    # 2. A brand-new identity must carry a verified email — the account is keyed on
    # it (username + collision denial), so an unverified claim is untrustworthy.
    if not identity.email_verified:
        raise OIDCProvisionError("email not verified")

    # 3. Email is a mutable display/contact attribute, never an identity key.
    normalized_email = identity.email.strip().lower()
    if await _email_owner(session, normalized_email) is not None:
        raise OIDCProvisionError("account linking required")

    # 4. JIT create. The (issuer, subject) authenticates this account; the email
    # cannot claim an existing row because every collision above is denied.
    username = normalized_email
    if (await session.exec(select(User).where(User.username == username))).first() is not None:
        # A local account whose username happens to be this email (with a
        # different/absent email of its own — same-email rows were denied above).
        username = _derive_username(normalized_email, identity)
    user = User(
        username=username,
        password_hash=None,
        email=normalized_email,
        is_admin=map_is_admin(cfg, identity),
        auth_provider=cfg.key,
        oidc_issuer=identity.issuer,
        oidc_subject=identity.subject,
        auth_tenant=identity.tenant_id,
        role_managed_by_idp=True,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        # A unique violation. It can be (a) a concurrent callback that JIT-created
        # this same (issuer, subject), (b) a concurrent first-time callback with a
        # DIFFERENT subject that won the same email (the partial unique index on SSO
        # email fires), or (c) the derived username was taken. Re-derive after the
        # rollback rather than assuming which — assuming "username only" is what
        # would let case (b) create a second account for one email.
        await session.rollback()
        existing = await _match_identity(session, identity, provider=cfg.key, lock=True)
        if existing is not None:
            await _sync_returning_user(session, cfg=cfg, identity=identity, user=existing)
            return existing, False
        # A concurrent callback from a different provider won this (issuer, subject)
        # (the global unique constraint fired) — deny cleanly, as the pre-insert
        # foreign-identity check would have (#226).
        if await _foreign_identity_exists(session, identity, provider=cfg.key):
            raise OIDCProvisionError("identity conflict") from None
        # A different identity took this email between our check and now — deny,
        # exactly as the initial collision check would have.
        if await _email_owner(session, normalized_email) is not None:
            raise OIDCProvisionError("account linking required") from None
        # Pure username collision — retry once with a wider, still-deterministic
        # suffix so a pre-existing squatter of the short form can't dead-end login.
        user.username = _derive_username(normalized_email, identity, width=32)
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            logger.warning("OIDC JIT provisioning conflict for provider %s", cfg.key)
            raise OIDCProvisionError("provisioning conflict") from None
    await session.refresh(user)
    logger.info("OIDC JIT-provisioned user %s via %s (admin=%s)", user.username, cfg.key, user.is_admin)
    return user, True
