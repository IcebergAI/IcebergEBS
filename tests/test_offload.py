"""Regression tests for issue #4 — CPU-bound work must run off the event loop.

bcrypt and package inspection are pure-CPU and, on the mandated single uvicorn
worker, would stall every concurrent request (and the scheduler) if run inline on
the asyncio event loop. These tests assert the work is offloaded to a worker
thread rather than executing on the event-loop thread.
"""
import threading
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

import app.auth as auth
import app.services as services
from app.auth import hash_password, verify_password
from app.fetchers.base import ExtensionMetadata
from app.inspector import PackageAnalysis
from app.models import Extension


# ---------------------------------------------------------------------------
# bcrypt
# ---------------------------------------------------------------------------

async def test_hash_and_verify_password_roundtrip():
    hashed = await hash_password("s3cret-passw0rd")
    assert hashed != "s3cret-passw0rd"
    assert await verify_password("s3cret-passw0rd", hashed) is True
    assert await verify_password("wrong", hashed) is False


async def test_hash_password_runs_off_event_loop_thread():
    main_thread = threading.get_ident()
    captured: dict[str, int] = {}
    real = auth._hash_password_sync

    def spy(password: str) -> str:
        captured["thread"] = threading.get_ident()
        return real(password)

    with patch.object(auth, "_hash_password_sync", spy):
        await hash_password("secret")

    assert captured["thread"] != main_thread


async def test_verify_password_runs_off_event_loop_thread():
    main_thread = threading.get_ident()
    captured: dict[str, int] = {}
    real = auth._verify_password_sync

    def spy(password: str, hashed: str) -> bool:
        captured["thread"] = threading.get_ident()
        return real(password, hashed)

    hashed = await hash_password("secret")
    with patch.object(auth, "_verify_password_sync", spy):
        await verify_password("secret", hashed)

    assert captured["thread"] != main_thread


# ---------------------------------------------------------------------------
# package inspection
# ---------------------------------------------------------------------------

async def test_inspect_package_runs_off_event_loop_thread(test_db, admin_user):
    """fetch_and_store must offload inspect_package so the loop stays responsive."""
    main_thread = threading.get_ident()
    captured: dict[str, int] = {}

    def spy(_data: bytes) -> PackageAnalysis:
        captured["thread"] = threading.get_ident()
        return PackageAnalysis(permissions=["storage"])

    meta = ExtensionMetadata(
        name="Off Ext", publisher="Pub", description=None, version="1.0.0",
        install_count=None, last_updated=None, store_url="https://example.com",
        publisher_verified=True,
    )

    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id, store="vscode", extension_id="off.ext",
            name="Off Ext", publisher="Pub", version="1.0.0",
            store_url="https://example.com", risk_score=10,
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)

        async with httpx.AsyncClient() as http:
            with patch("app.fetchers.VSCodeFetcher") as MockFetcher:
                MockFetcher.return_value.fetch = AsyncMock(
                    return_value=(meta, b"PK\x03\x04-fake-package-bytes")
                )
                with patch.object(services, "inspect_package", spy):
                    await services.fetch_and_store(ext, session, http)

    assert captured["thread"] != main_thread
