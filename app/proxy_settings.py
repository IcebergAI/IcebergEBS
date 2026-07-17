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


async def get_settings(session: AsyncSession) -> ProxySettings:
    """Return the singleton row, seeding it from env defaults on first read."""
    row = await session.get(ProxySettings, _SINGLETON_ID)
    if row is None:
        row = ProxySettings(
            id=_SINGLETON_ID,
            mode=_seed_mode(),
            proxy_url=settings.proxy_url,
            no_proxy=settings.proxy_no_proxy,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row


async def update_settings(session: AsyncSession, changes: dict[str, Any]) -> ProxySettings:
    """Apply a whitelisted patch to the singleton row and refresh the snapshot."""
    row = await get_settings(session)
    for key in EDITABLE_FIELDS:
        if key in changes and changes[key] is not None:
            setattr(row, key, changes[key])
    row.updated_at = _utcnow()
    session.add(row)
    await session.commit()
    await session.refresh(row)
    proxy.set_config(_to_config(row))
    return row


async def refresh_cache(session: AsyncSession) -> None:
    """Load the singleton row into the in-memory snapshot (startup)."""
    row = await get_settings(session)
    proxy.set_config(_to_config(row))
