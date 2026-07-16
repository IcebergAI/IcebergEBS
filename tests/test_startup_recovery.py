"""#155: startup pending-alert recovery must run as a BACKGROUND task.

Running it inline before the lifespan `yield` delayed the point at which uvicorn
binds and answers probes by up to (pending extensions × webhook timeout) — a
backlog behind a dead destination could exceed the liveness window and get the
pod killed mid-recovery. These drive the real lifespan (heavy startup steps
stubbed) and assert startup no longer blocks on recovery, and that shutdown
cancels an in-flight recovery instead of hanging on it.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app import main as main_module


def _stub_startup(monkeypatch):
    """Stub the heavy/side-effecting startup steps so only recovery scheduling runs."""
    monkeypatch.setattr(main_module, "init_db", AsyncMock())
    monkeypatch.setattr("app.auth.seed_admin", AsyncMock())
    monkeypatch.setattr(main_module, "create_scheduler", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(main_module, "drain_inflight", AsyncMock())


async def test_startup_does_not_block_on_recovery(monkeypatch):
    _stub_startup(monkeypatch)

    started = asyncio.Event()
    proceed = asyncio.Event()

    async def blocking_recover(engine, client):
        started.set()
        await proceed.wait()

    monkeypatch.setattr("app.services.recover_pending_alerts", blocking_recover)

    app = main_module.app
    async with main_module.lifespan(app):
        # If recovery were awaited inline, entering this block would deadlock on `proceed`.
        # Reaching here at all proves startup did not block on it.
        await asyncio.wait_for(started.wait(), timeout=2)  # it did start, concurrently
        task = app.state.recovery_task
        assert isinstance(task, asyncio.Task)
        assert not task.done()  # startup returned while recovery is still running
        proceed.set()
        await asyncio.wait_for(task, timeout=2)  # let it finish before shutdown
    assert app.state.recovery_task.done()


async def test_shutdown_cancels_inflight_recovery(monkeypatch):
    _stub_startup(monkeypatch)

    started = asyncio.Event()

    async def never_finishes(engine, client):
        started.set()
        await asyncio.Event().wait()  # blocks forever unless cancelled

    monkeypatch.setattr("app.services.recover_pending_alerts", never_finishes)

    app = main_module.app
    async with main_module.lifespan(app):
        await asyncio.wait_for(started.wait(), timeout=2)
        task = app.state.recovery_task
        assert not task.done()
    # Shutdown must cancel the still-running recovery rather than hang on the dead webhook.
    assert task.cancelled()


async def test_background_recovery_failure_does_not_break_lifespan(monkeypatch):
    """A recovery exception is logged, not propagated — it must not crash startup/shutdown."""
    _stub_startup(monkeypatch)

    async def boom(engine, client):
        raise RuntimeError("db unreachable")

    monkeypatch.setattr("app.services.recover_pending_alerts", boom)

    app = main_module.app
    async with main_module.lifespan(app):
        await asyncio.wait_for(app.state.recovery_task, timeout=2)
    # The wrapper swallowed the error (logged it); the task completed without cancellation.
    assert app.state.recovery_task.done()
    assert not app.state.recovery_task.cancelled()
    assert app.state.recovery_task.exception() is None
