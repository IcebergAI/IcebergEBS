"""Manage the singleton OIDCSettings row + the in-memory SSO config snapshot (#32).

Mirrors app/proxy_settings.py (#216): the row (``id == 1``) is the admin-editable
SSO config, seeded from the ``ICEBERG_EBS_AUTH_MODE`` / ``ICEBERG_EBS_OIDC_*`` env
on first read; after that the row is the source of truth, editable at
/admin/oidc. Client secrets are env-only and never touch the row.

Unlike the proxy snapshot (consulted per request), Authlib caches its registered
clients, so every config change must also ``reset_registration()`` — the routes
re-register lazily on the next SSO request. ``refresh_cache`` is the startup
loader and is deliberately fail-closed: an invalid stored/env config aborts boot
rather than silently starting with SSO half-configured (an OIDC-only deployment
would otherwise fail open to... nothing — no working login path at all).
"""

from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import OIDCSettings, _utcnow
from app.oidc.config import (
    EDITABLE_FIELDS,
    OIDCRuntimeConfig,
    env_config,
    validate_config,
)

_SINGLETON_ID = 1

_config: OIDCRuntimeConfig | None = None


def get_config() -> OIDCRuntimeConfig:
    """The active SSO config: the loaded DB snapshot, else the env seed."""
    return _config or env_config()


def set_config(config: OIDCRuntimeConfig | None) -> None:
    global _config
    _config = config


def _to_config(row: OIDCSettings) -> OIDCRuntimeConfig:
    return OIDCRuntimeConfig(**{f: getattr(row, f) for f in EDITABLE_FIELDS})


async def ensure_seeded(session: AsyncSession) -> OIDCSettings:
    """Seed the singleton row from the (validated) env if missing; return it.

    The single seed path (startup ``refresh_cache``, and ``update_settings`` so it's
    robust standalone) — seeding no longer lives in the read path, so ``get_settings``
    can't commit mid-request. Concurrency-safe: two first-readers racing the INSERT
    both survive — the loser folds the ``IntegrityError`` into a re-read instead of
    500ing, matching ``update_settings``' IntegrityError discipline.
    """
    row = await session.get(OIDCSettings, _SINGLETON_ID)
    if row is not None:
        return row
    candidate = env_config()
    validate_config(candidate)
    row = OIDCSettings(id=_SINGLETON_ID, **{f: getattr(candidate, f) for f in EDITABLE_FIELDS})
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        seeded = await session.get(OIDCSettings, _SINGLETON_ID)
        if seeded is None:  # a concurrent seed won then vanished — genuinely broken
            raise
        return seeded
    await session.refresh(row)
    return row


async def get_settings(session: AsyncSession) -> OIDCSettings:
    """Return the singleton row. Read-only: it's seeded at startup by ``refresh_cache``
    (and by ``update_settings``), so this never commits — a commit here would expire
    every instance loaded in the request session, e.g. the admin page's current_user."""
    row = await session.get(OIDCSettings, _SINGLETON_ID)
    if row is None:
        raise RuntimeError("OIDCSettings singleton missing — ensure_seeded must run at startup")
    return row


async def update_settings(session: AsyncSession, changes: dict[str, Any]) -> OIDCSettings:
    """Apply a whitelisted patch to the singleton row and refresh the snapshot.

    Validation runs on the RESULTING config under a ``FOR UPDATE`` row lock —
    validating the request fields alone would be a TOCTOU: two concurrent PUTs
    (one setting auth_mode=oidc, one disabling the last provider) can each pass a
    pre-check and interleave into an OIDC-only config with no provider — a full
    lockout. ``populate_existing=True`` is load-bearing: without it a locking
    ``session.get`` returns the identity-map instance without refreshing, so a
    writer that queued behind the lock would validate stale pre-commit state.
    Raises ``ValueError`` on an invalid result.
    """
    await ensure_seeded(session)  # guarantee the singleton exists before locking it
    row = await session.get(OIDCSettings, _SINGLETON_ID, with_for_update=True, populate_existing=True)
    if row is None:  # just seeded above and never deleted — unreachable in practice
        raise RuntimeError("OIDCSettings singleton row missing")
    current = _to_config(row)
    candidate = OIDCRuntimeConfig(
        **{f: changes[f] if f in changes and changes[f] is not None else getattr(current, f) for f in EDITABLE_FIELDS}
    )
    try:
        validate_config(candidate)
    except ValueError:
        await session.rollback()  # discard the patch and release the row lock
        raise
    if candidate == current:
        # No-op save (the admin JS PUTs the whole form on every click). Skip the
        # write, the commit, and — crucially — reset_registration(): rebinding the
        # Authlib registry discards every provider's cached discovery doc + JWKS,
        # forcing the next login per provider to re-fetch both over the network.
        await session.rollback()  # release the row lock; nothing to persist
        return row
    for f in EDITABLE_FIELDS:
        setattr(row, f, getattr(candidate, f))
    row.updated_at = _utcnow()
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        # A schema CHECK fired (junk auth_mode / oidc-only with no provider). Only
        # reachable by a writer racing outside this function's validate+lock
        # discipline; fold it into the same ValueError the route maps to 422, mirroring
        # proxy_settings rather than surfacing a raw 500.
        await session.rollback()
        raise ValueError("invalid OIDC configuration") from exc
    await session.refresh(row)
    set_config(_to_config(row))
    # Deferred import: app/oidc/service.py reads get_config() from this module.
    from app.oidc import service as oidc_service

    oidc_service.reset_registration()
    return row


async def refresh_cache(session: AsyncSession) -> None:
    """Seed (if missing), then load + validate the stored config into the snapshot
    (startup, fail-closed)."""
    row = await ensure_seeded(session)
    config = _to_config(row)
    validate_config(config)
    set_config(config)
    from app.oidc import service as oidc_service

    oidc_service.reset_registration()
