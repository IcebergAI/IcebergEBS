import logging

import bcrypt
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.database import engine, get_session

logger = logging.getLogger(__name__)

_serializer = URLSafeTimedSerializer(settings.secret_key)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


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


async def verify_credentials(username: str, password: str, session: AsyncSession):
    """Return the User if credentials are valid, None otherwise."""
    from app.models import User
    user = (await session.exec(select(User).where(User.username == username))).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None


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


async def require_admin(current_user=Depends(require_auth)):
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
            password_hash=hash_password(settings.admin_password),
            is_admin=True,
        )
        session.add(user)
        await session.commit()
