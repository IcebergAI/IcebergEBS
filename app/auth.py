import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Annotated

import anyio.to_thread
import bcrypt
from fastapi import Depends, HTTPException, Request
from fastapi.security.utils import get_authorization_scheme_param
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine, get_session

logger = logging.getLogger(__name__)

_serializer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())


def generate_api_key() -> str:
    """Return a new raw API key. Caller must store only the hash."""
    return "marvin_" + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest of the raw key. API keys are 256-bit random so SHA-256 is sufficient."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _hash_password_sync(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password_sync(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


async def hash_password(password: str) -> str:
    """Hash a password with bcrypt, offloaded to a worker thread.

    bcrypt is ~100ms of pure CPU per call; running it inline on the single-worker
    event loop stalls every concurrent request and the scheduler (issue #4).
    """
    return await anyio.to_thread.run_sync(_hash_password_sync, password)


async def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash, offloaded to a worker thread."""
    return await anyio.to_thread.run_sync(_verify_password_sync, password, hashed)


def create_session_cookie(username: str) -> str:
    return _serializer.dumps({"u": username})


def get_current_user(request: Request) -> str | None:
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        return None
    try:
        data = _serializer.loads(cookie, max_age=settings.session_max_age)
        return data["u"]
    except (SignatureExpired, BadSignature, KeyError):
        return None


# Pre-computed dummy hash used when the username doesn't exist, so the bcrypt
# work factor is always paid regardless of whether the username is valid.
# This prevents username enumeration via response-time differences.
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)).decode()


async def verify_credentials(username: str, password: str, session: AsyncSession):
    """Return the User if credentials are valid, None otherwise."""
    from app.models import User
    user = (await session.exec(select(User).where(User.username == username))).first()
    hash_to_check = user.password_hash if user else _DUMMY_HASH
    valid = await verify_password(password, hash_to_check)
    return user if (user and valid) else None


async def require_auth(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """FastAPI dependency — returns the authenticated User or redirects to /login."""
    from app.models import User
    username = get_current_user(request)
    if username is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    user = (await session.exec(select(User).where(User.username == username))).first()
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


async def require_api_auth(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """FastAPI dependency for /api/* routes.

    Tries Bearer token first, then session cookie. Always returns a User or
    raises HTTPException(401) — never redirects.
    """
    from app.models import ApiKey, User

    scheme, raw_key = get_authorization_scheme_param(
        request.headers.get("Authorization", "")
    )
    if scheme.lower() == "bearer" and raw_key:
        key_hash = hash_api_key(raw_key)
        api_key = (await session.exec(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        )).first()
        if api_key is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if api_key.readonly and request.method not in ("GET", "HEAD"):
            raise HTTPException(status_code=403, detail="Read-only API key")
        user_id = api_key.user_id  # capture before commit expires the object
        # Throttle the last_used_at write: on SQLite the commit takes the single
        # write lock, contending with the scheduler, and would otherwise fire on
        # every request (including read-only GETs). Only write when the recorded
        # value is missing or older than the configured window.
        now = datetime.now(timezone.utc)
        last_used = api_key.last_used_at
        if last_used is not None and last_used.tzinfo is None:
            last_used = last_used.replace(tzinfo=timezone.utc)
        if (
            last_used is None
            or (now - last_used).total_seconds()
            >= settings.api_key_last_used_throttle_seconds
        ):
            api_key.last_used_at = now
            session.add(api_key)
            await session.commit()
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return user

    # Fall back to session cookie
    username = get_current_user(request)
    if username is not None:
        from app.models import User
        user = (await session.exec(select(User).where(User.username == username))).first()
        if user is not None:
            return user

    raise HTTPException(status_code=401, detail="Authentication required")


async def require_admin(current_user=Depends(require_api_auth)):
    """FastAPI dependency — requires the authenticated user to be an admin."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def set_session(response, username: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=create_session_cookie(username),
        max_age=settings.session_max_age,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
    )


def clear_session(response) -> None:
    response.delete_cookie(key=settings.session_cookie_name)


async def seed_admin() -> None:
    """Create the initial admin user from env vars if no users exist."""
    from app.models import User
    async with AsyncSession(engine) as session:
        existing = (await session.exec(select(User))).first()
        if existing:
            return
        logger.info("No users found — seeding admin user '%s'", settings.admin_username)
        user = User(
            username=settings.admin_username,
            password_hash=await hash_password(settings.admin_password.get_secret_value()),
            is_admin=True,
        )
        session.add(user)
        await session.commit()
