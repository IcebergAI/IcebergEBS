import io
import json

# Override settings before importing app modules
import os
import zipfile
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

os.environ.setdefault("ICEBERG_EBS_ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ICEBERG_EBS_ADMIN_PASSWORD", "testpass")
os.environ.setdefault("ICEBERG_EBS_SECRET_KEY", "test-secret-key-for-testing-only-32chars")

from app.auth import create_session_cookie, generate_api_key, hash_api_key, hash_password
from app.config import settings
from app.database import get_session
from app.main import app
from app.models import ApiKey, User

# The suite runs against a real Postgres (dev compose service / CI service container).
# Point it via ICEBERG_EBS_TEST_DATABASE_URL; otherwise fall back to the app's configured URL.
TEST_DATABASE_URL = os.environ.get("ICEBERG_EBS_TEST_DATABASE_URL", settings.database_url)


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
        zf.writestr(
            "extension/manifest.json",
            json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test Extension",
                    "version": "1.2.3",
                    "permissions": ["storage"],
                }
            ),
        )
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


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def test_db():
    """Shared Postgres engine for the whole test session.

    The schema is created once (the models == migrations head; migrations
    themselves are exercised by tests/test_migrations.py). Per-test isolation is
    provided by the autouse ``_clean_tables`` fixture, which TRUNCATEs every table
    after each test.
    """
    test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    yield test_engine
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def _clean_tables(test_db):
    """Reset every table after each test so the next starts from a clean DB."""
    yield
    table_list = ", ".join(f'"{t.name}"' for t in SQLModel.metadata.sorted_tables)
    if not table_list:
        return
    async with test_db.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def session(test_db):
    async with AsyncSession(test_db) as s:
        yield s


@pytest_asyncio.fixture
async def admin_user(test_db) -> User:
    """Insert the testadmin user into the test DB."""
    async with AsyncSession(test_db) as s:
        user = User(
            username="testadmin",
            password_hash=await hash_password("testpass"),
            is_admin=True,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        return user


@pytest_asyncio.fixture
async def client(test_db, admin_user):
    """Authenticated test client backed by the shared test DB."""

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
async def api_key_client(test_db, admin_user):
    """Authenticated test client using Bearer token instead of session cookie."""

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session

    mock_http = MagicMock()
    app.state.http_client = mock_http

    raw_key = generate_api_key()
    async with AsyncSession(test_db) as s:
        s.add(ApiKey(user_id=admin_user.id, label="test-key", key_hash=hash_api_key(raw_key)))
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {raw_key}"},
    ) as c:
        yield c

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def readonly_api_key_client(test_db, admin_user):
    """Authenticated test client with a read-only Bearer token."""

    async def override_session():
        async with AsyncSession(test_db) as s:
            yield s

    app.dependency_overrides[get_session] = override_session

    mock_http = MagicMock()
    app.state.http_client = mock_http

    raw_key = generate_api_key()
    async with AsyncSession(test_db) as s:
        s.add(
            ApiKey(
                user_id=admin_user.id,
                label="readonly-test-key",
                key_hash=hash_api_key(raw_key),
                readonly=True,
            )
        )
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {raw_key}"},
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
