"""Manage the singleton ProxySettings row + the in-memory proxy snapshot (#216).

The row (``id == 1``) is the admin-editable routing config; on first read it is
seeded from the ``ICEBERG_EBS_PROXY_*`` env defaults. Every update pushes a
``ProxyConfig`` snapshot into ``app.proxy`` so ``ProxyRoutingTransport`` can
route each request without touching the DB. Unlike deep_thought's original
there is no dependent-cache invalidation step: the routing transport consults
the snapshot per request, so a save takes effect on the very next outbound
request with no client rebuild.
"""

from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from app import proxy
from app.config import settings
from app.models import ProxySettings, _utcnow

_SINGLETON_ID = 1

# Fields an admin may change. Credentials are intentionally absent — they are
# env-only and never reach the DB. Used to whitelist PUT payloads.
EDITABLE_FIELDS = ("mode", "proxy_url", "no_proxy")


def _to_config(row: ProxySettings) -> proxy.ProxyConfig:
    return proxy.ProxyConfig(mode=row.mode, proxy_url=row.proxy_url, no_proxy=row.no_proxy)


def _seed_mode() -> str:
    """Env-seeded mode, normalised to the enum's spelling (SYSTEM on anything odd)."""
    try:
        return proxy.ProxyMode(settings.proxy_mode.strip().upper()).value
    except ValueError:
        return proxy.ProxyMode.SYSTEM.value


async def ensure_seeded(session: AsyncSession) -> ProxySettings:
    """Seed the singleton row from env defaults if missing; return it.

    The single seed path (startup ``refresh_cache``, and ``update_settings`` so it's
    robust standalone) — seeding no longer lives in the read path, so ``get_settings``
    can't commit mid-request. Concurrency-safe: two first-readers racing the INSERT
    both survive — the loser folds the ``IntegrityError`` into a re-read instead of
    500ing, matching the IntegrityError discipline in ``update_settings``.
    """
    row = await session.get(ProxySettings, _SINGLETON_ID)
    if row is not None:
        return row
    row = ProxySettings(
        id=_SINGLETON_ID,
        mode=_seed_mode(),
        proxy_url=settings.proxy_url,
        no_proxy=settings.proxy_no_proxy,
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        row = await session.get(ProxySettings, _SINGLETON_ID)
        if row is None:  # a concurrent seed won then vanished — genuinely broken
            raise
        return row
    await session.refresh(row)
    return row


async def get_settings(session: AsyncSession) -> ProxySettings:
    """Return the singleton row. Read-only: it's seeded at startup by ``refresh_cache``
    (and by ``update_settings``), so this never commits — a commit here would expire
    every instance loaded in the request session, e.g. the admin page's current_user."""
    row = await session.get(ProxySettings, _SINGLETON_ID)
    if row is None:
        raise RuntimeError("ProxySettings singleton missing — ensure_seeded must run at startup")
    return row


async def update_settings(session: AsyncSession, changes: dict[str, Any]) -> ProxySettings:
    """Apply a whitelisted patch to the singleton row and refresh the snapshot.

    The EXPLICIT⇒URL invariant is enforced HERE, on the resulting row, under a
    ``FOR UPDATE`` row lock — validating before the update (in the route) is a
    TOCTOU: two concurrent PUTs can each pass a pre-check and interleave into
    EXPLICIT-with-empty-URL, silently failing open to direct egress. The lock
    serialises writers, and ``populate_existing=True`` is load-bearing: without
    it a locking ``session.get`` returns the identity-map instance WITHOUT
    refreshing its attributes, so a writer that queued behind the lock would
    validate the stale pre-commit state instead of what the winner just wrote.
    The schema-level CHECK constraint (see ``models.ProxySettings``) backstops
    any writer that bypasses this function; a constraint rejection is folded
    into the same error path. Raises ``ValueError`` on violation.
    """
    await ensure_seeded(session)  # guarantee the singleton exists before locking it
    row = await session.get(ProxySettings, _SINGLETON_ID, with_for_update=True, populate_existing=True)
    if row is None:  # just seeded above and never deleted — unreachable in practice
        raise RuntimeError("ProxySettings singleton row missing")
    for key in EDITABLE_FIELDS:
        if key in changes and changes[key] is not None:
            setattr(row, key, changes[key])
    if row.mode == proxy.ProxyMode.EXPLICIT.value and not row.proxy_url.strip():
        await session.rollback()  # discard the patch and release the row lock
        raise ValueError("explicit mode requires a proxy URL")
    row.updated_at = _utcnow()
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        # The CHECK constraint fired — only reachable by a writer racing outside
        # this function's lock discipline. Same client-facing error either way.
        await session.rollback()
        raise ValueError("explicit mode requires a proxy URL") from exc
    await session.refresh(row)
    proxy.set_config(_to_config(row))
    return row


async def refresh_cache(session: AsyncSession) -> None:
    """Seed (if missing) and load the singleton row into the in-memory snapshot (startup)."""
    row = await ensure_seeded(session)
    proxy.set_config(_to_config(row))
