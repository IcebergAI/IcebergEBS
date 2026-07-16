"""#155: lifespan startup must NOT run pending-alert recovery.

Running recover_pending_alerts inline before the lifespan `yield` delayed the
point at which uvicorn binds and answers probes by up to (pending extensions ×
webhook timeout) — a backlog behind a dead destination could exceed the liveness
window and get the pod killed mid-recovery. Recovery is deferred to the head of
each scheduler refresh cycle instead, backed by the durable pending-alert marker
(#109), which also keeps recovery running in exactly one place so it can't race a
concurrent refresh's delivery. This drives the real lifespan (heavy startup steps
stubbed) and asserts startup neither calls recovery nor blocks.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app import main as main_module


def _stub_startup(monkeypatch):
    """Stub the heavy/side-effecting startup steps so only the recovery decision runs."""
    monkeypatch.setattr(main_module, "init_db", AsyncMock())
    monkeypatch.setattr("app.auth.seed_admin", AsyncMock())
    monkeypatch.setattr(main_module, "create_scheduler", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(main_module, "drain_inflight", AsyncMock())


async def test_startup_does_not_run_recovery(monkeypatch):
    _stub_startup(monkeypatch)

    recover = AsyncMock()
    monkeypatch.setattr("app.services.recover_pending_alerts", recover)

    app = main_module.app
    async with main_module.lifespan(app):
        # Recovery is deferred to the scheduler cycle, not run at startup — so a slow/dead
        # webhook destination can never block the server from binding or answering probes.
        recover.assert_not_called()
    recover.assert_not_called()


async def test_startup_completes_even_if_recovery_would_block(monkeypatch):
    """Belt-and-braces: even a recovery that would hang forever must not be able to stall
    startup, because startup doesn't await it at all."""
    _stub_startup(monkeypatch)

    async def would_hang(engine, client):
        await asyncio.Event().wait()  # blocks forever if ever awaited

    monkeypatch.setattr("app.services.recover_pending_alerts", would_hang)

    app = main_module.app
    # If startup awaited recovery, entering this context would hang and time out.
    async with asyncio.timeout(5):
        async with main_module.lifespan(app):
            pass
