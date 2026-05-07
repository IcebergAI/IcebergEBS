import io
import json
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

# Override settings before importing app modules
import os
os.environ.setdefault("MARVIN_ADMIN_USERNAME", "testadmin")
os.environ.setdefault("MARVIN_ADMIN_PASSWORD", "testpass")
os.environ.setdefault("MARVIN_SECRET_KEY", "test-secret-key-for-testing-only-32chars")

from app.main import app
from app.config import settings
from app.database import get_session
from app.auth import create_session_cookie, hash_password
from app.models import User


def make_fake_vsix(manifest: dict | None = None) -> bytes:
    """Build a minimal .vsix zip for testing."""
    if manifest is None:
        manifest = {
            "name": "test-ext",
            "displayName": "Test Extension",
            "version": "1.2.3",
            "publisher": {"publisherName": "testpublisher", "isDomainVerified": True},
        }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pkg = {
            "name": "test-ext",
            "version": "1.2.3",
            "contributes": {},
        }
        zf.writestr("extension/package.json", json.dumps(pkg))
        zf.writestr("extension/manifest.json", json.dumps({
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.2.3",
            "permissions": ["storage"],
        }))
        zf.writestr("extension/background.js", 'console.log("hello");')
    return buf.getvalue()


def make_fake_crx(manifest: dict | None = None) -> bytes:
    """Build a fake CRX (just a zip with a PK magic at start)."""
    if manifest is None:
        manifest = {
            "manifest_version": 3,
            "name": "Chrome Test",
            "version": "2.0.0",
            "permissions": ["tabs", "storage"],
        }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("background.js", "console.log('bg');")
    return buf.getvalue()


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def test_db():
    """In-memory SQLite for each test."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield test_engine
    await test_engine.dispose()


@pytest_asyncio.fixture
async def session(test_db):
    async with AsyncSession(test_db) as s:
        yield s


@pytest_asyncio.fixture
async def admin_user(test_db) -> User:
    """Insert the testadmin user into the in-memory DB."""
    async with AsyncSession(test_db) as s:
        user = User(
            username="testadmin",
            password_hash=hash_password("testpass"),
            is_admin=True,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        return user


@pytest_asyncio.fixture
async def client(test_db, admin_user):
    """Authenticated test client with in-memory DB."""
    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session

    # Mock the http_client on app.state
    mock_http = MagicMock()
    app.state.http_client = mock_http

    cookie = create_session_cookie("testadmin")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={settings.session_cookie_name: cookie},
    ) as c:
        yield c

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def anon_client(test_db):
    """Unauthenticated test client."""
    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
