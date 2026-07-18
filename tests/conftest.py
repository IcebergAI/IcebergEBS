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
# Enable one OIDC provider (#32) so the SSO routes register and the login page
# renders a button; discovery/JWKS are never fetched — tests stub the Authlib
# client boundary (tests/test_oidc.py). AUTH_MODE stays the default "both".
os.environ.setdefault("ICEBERG_EBS_OIDC_AUTHENTIK_ENABLED", "true")
os.environ.setdefault("ICEBERG_EBS_OIDC_AUTHENTIK_BASE_URL", "https://authentik.test")
os.environ.setdefault("ICEBERG_EBS_OIDC_AUTHENTIK_APP_SLUG", "iceberg-ebs")
os.environ.setdefault("ICEBERG_EBS_OIDC_AUTHENTIK_CLIENT_ID", "test-client-id")
os.environ.setdefault("ICEBERG_EBS_OIDC_AUTHENTIK_CLIENT_SECRET", "test-client-secret")

from app.auth import _hash_password_sync, create_session_cookie, generate_api_key, hash_api_key
from app.config import settings
from app.database import get_session
from app.main import app
from app.models import ApiKey, User

# The suite runs against a real Postgres (dev compose service / CI service container).
# Point it via ICEBERG_EBS_TEST_DATABASE_URL; otherwise fall back to the app's configured URL.
TEST_DATABASE_URL = os.environ.get("ICEBERG_EBS_TEST_DATABASE_URL", settings.database_url)


def make_zip(files: dict[str, str | bytes]) -> bytes:
    """Build an in-memory zip from a {name: content} mapping.

    The single fake-package builder for the suite — every VSIX/CRX test payload
    (here, test_api, test_fetchers, test_inspector) is a thin wrapper over this,
    so the zip-construction boilerplate lives in one place.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def make_fake_vsix() -> bytes:
    """Build a minimal .vsix zip for testing."""
    return make_zip(
        {
            "extension/package.json": json.dumps({"name": "test-ext", "version": "1.2.3", "contributes": {}}),
            "extension/manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test Extension",
                    "version": "1.2.3",
                    "permissions": ["storage"],
                }
            ),
            "extension/background.js": 'console.log("hello");',
        }
    )


def make_fake_crx(manifest: dict | None = None) -> bytes:
    """Build a fake CRX (a bare zip — deliberately no CRX header; real
    CRX-header stripping is exercised separately in test_fetchers)."""
    if manifest is None:
        manifest = {
            "manifest_version": 3,
            "name": "Chrome Test",
            "version": "2.0.0",
            "permissions": ["tabs", "storage"],
        }
    return make_zip({"manifest.json": json.dumps(manifest), "background.js": "console.log('bg');"})


# bcrypt at the production work factor (BCRYPT_ROUNDS=12) costs ~250ms of pure CPU
# per call, and the admin_user fixture runs for most of the suite — re-hashing the
# same literal password every test dominated runtime. The salt lives inside the
# hash, so one hash per distinct password is a real production-cost hash that
# verifies identically everywhere (login tests included).
_password_hash_cache: dict[str, str] = {}


def cached_password_hash(password: str) -> str:
    """Bcrypt-hash *password* at the production work factor, once per session."""
    if password not in _password_hash_cache:
        _password_hash_cache[password] = _hash_password_sync(password)
    return _password_hash_cache[password]


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _reset_oidc_state():
    """Reset the in-memory SSO config snapshot + Authlib registration around every
    test (#32) — a test that set_config()s or registers providers must not leak
    into the next (the OIDCSettings row itself is handled by _clean_tables)."""
    from app import oidc_settings
    from app.oidc import service as oidc_service

    oidc_settings.set_config(None)
    oidc_service.reset_registration()
    yield
    oidc_settings.set_config(None)
    oidc_service.reset_registration()


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
        # alembic_version is not a SQLModel table, so drop_all never touches it.
        # Start from a truly clean DB so a stamp inherited from a prior app boot
        # can't linger under the create_all'd schema (#113).
        await conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
        await conn.run_sync(SQLModel.metadata.create_all)
    yield test_engine
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        # Leave the dev DB bootable for a subsequent `make dev`: dropping only the
        # SQLModel tables would leave alembic_version stamped at head, so init_db
        # would trust the stamp, run no migrations, and the app would meet an
        # empty schema (#113). Dropping it makes the next boot migrate from scratch.
        await conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
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


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def _seed_settings_singletons(test_db):
    """Seed the proxy/OIDC settings singletons before each test (#234).

    Production seeds them in the lifespan (``refresh_cache``); the ASGITransport test
    client doesn't run lifespan, and ``get_settings`` is now read-only (seeding moved
    out of the request path), so the row must exist up front. Runs after the prior
    test's ``_clean_tables`` TRUNCATE, mirroring a fresh startup."""
    from app import oidc_settings, proxy_settings

    async with AsyncSession(test_db) as s:
        await proxy_settings.ensure_seeded(s)
        await oidc_settings.ensure_seeded(s)
    yield


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
            password_hash=cached_password_hash("testpass"),
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
        # Real browsers send Origin on state-changing requests; the CSRF origin
        # check (#107) requires it on cookie-authenticated POST/PUT/PATCH/DELETE.
        headers={"Origin": "http://test"},
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
    # Same-origin Origin, as a real browser sends on state-changing requests; the CSRF
    # origin check (#107) now covers unauthenticated posts (e.g. /login) too.
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Origin": "http://test"}) as c:
        yield c

    app.dependency_overrides.clear()
