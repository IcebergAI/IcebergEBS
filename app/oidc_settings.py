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


async def get_settings(session: AsyncSession) -> OIDCSettings:
    """Return the singleton row, seeding it from the (validated) env on first read."""
    row = await session.get(OIDCSettings, _SINGLETON_ID)
    if row is None:
        candidate = env_config()
        validate_config(candidate)
        row = OIDCSettings(id=_SINGLETON_ID, **{f: getattr(candidate, f) for f in EDITABLE_FIELDS})
        session.add(row)
        await session.commit()
        await session.refresh(row)
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
    await get_settings(session)  # ensure the singleton exists (seeds on first read)
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
    for f in EDITABLE_FIELDS:
        setattr(row, f, getattr(candidate, f))
    row.updated_at = _utcnow()
    session.add(row)
    await session.commit()
    await session.refresh(row)
    set_config(_to_config(row))
    # Deferred import: app/oidc/service.py reads get_config() from this module.
    from app.oidc import service as oidc_service

    oidc_service.reset_registration()
    return row


async def refresh_cache(session: AsyncSession) -> None:
    """Load + validate the stored config into the snapshot (startup, fail-closed)."""
    row = await get_settings(session)
    config = _to_config(row)
    validate_config(config)
    set_config(config)
    from app.oidc import service as oidc_service

    oidc_service.reset_registration()
