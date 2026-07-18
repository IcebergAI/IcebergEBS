import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
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
from app.models import User

logger = logging.getLogger(__name__)

_serializer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())

# Single source of truth for the bcrypt work factor. Both real password hashing
# and the dummy-hash timing defense MUST use it, so they can never drift apart
# (a divergence would silently reintroduce the username-enumeration oracle — D4).
BCRYPT_ROUNDS = 12


def generate_api_key() -> str:
    """Return a new raw API key. Caller must store only the hash."""
    return "ebs_" + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest of the raw key. API keys are 256-bit random so SHA-256 is sufficient."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# bcrypt hashes only the first 72 bytes of its input; a longer password is either
# silently truncated (older bcrypt) or rejected (recent bcrypt). Silent truncation
# would let two distinct passwords sharing a 72-byte prefix hash identically (#67),
# so reject an over-long password explicitly instead of truncating it. The hashing
# itself is unchanged, so existing stored hashes verify as-is (no migration).
MAX_PASSWORD_BYTES = 72


class PasswordTooLongError(ValueError):
    """A password exceeds bcrypt's 72-byte hashing limit (#67)."""


def _hash_password_sync(password: str) -> str:
    encoded = password.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


def _verify_password_sync(password: str, hashed: str) -> bool:
    encoded = password.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        # No stored hash can match — over-long passwords are rejected at set time, and
        # recent bcrypt raises on >72-byte input. Rejecting here for known and unknown
        # users alike keeps the constant-time username-enumeration defense intact.
        return False
    return bcrypt.checkpw(encoded, hashed.encode())


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


def get_session_claims(request: Request) -> tuple[str, datetime] | None:
    """Return (username, cookie-issued-at) from a valid session cookie, else None.

    The issued-at timestamp is signed into the cookie by URLSafeTimedSerializer; it
    lets callers reject sessions older than the user's last password change (M1).
    """
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        return None
    try:
        data, issued_at = _serializer.loads(cookie, max_age=settings.session_max_age, return_timestamp=True)
        return data["u"], issued_at
    except (SignatureExpired, BadSignature, KeyError):
        return None


def get_current_user(request: Request) -> str | None:
    claims = get_session_claims(request)
    return claims[0] if claims else None


def _session_after_password_change(user, issued_at: datetime) -> bool:
    """True if a cookie issued at ``issued_at`` is still valid for ``user``.

    Cookies signed before the user's ``password_changed_at`` are stale (the
    password was reset on another device). A 1s tolerance absorbs the serializer's
    whole-second timestamp granularity so a fresh post-reset login isn't rejected.
    """
    changed = user.password_changed_at
    if changed is None:
        return True
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    return issued_at >= changed - timedelta(seconds=1)


def _session_within_sso_max_age(user, issued_at: datetime) -> bool:
    """True unless ``user`` is an SSO account whose cookie is older than the shorter
    SSO session lifetime (#221).

    An IdP-side disable/reset can't be pushed to us, so SSO sessions expire faster
    than local ones and force re-authentication through the IdP (which fails for a
    disabled account) — bounding how long a stale session or stolen cookie lives.
    Local accounts (no ``oidc_subject``) keep the full ``session_max_age``.
    """
    if user.oidc_subject is None:
        return True
    age = (datetime.now(timezone.utc) - issued_at).total_seconds()
    return age <= settings.oidc_session_max_age


# Pre-computed dummy hash used when the username doesn't exist, so the bcrypt
# work factor is always paid regardless of whether the username is valid.
# This prevents username enumeration via response-time differences.
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


async def verify_credentials(username: str, password: str, session: AsyncSession):
    """Return the User if credentials are valid, None otherwise.

    SSO-provisioned accounts have no local password (password_hash is NULL, #32);
    they take the dummy-hash path like unknown usernames — always paying the
    bcrypt cost, always failing — so password login can neither succeed for them
    nor leak their existence via timing.
    """
    user = (await session.exec(select(User).where(User.username == username))).first()
    stored_hash = user.password_hash if user else None
    valid = await verify_password(password, stored_hash or _DUMMY_HASH)
    return user if (user and stored_hash and valid) else None


async def authenticate_session(request: Request, session: AsyncSession) -> User | None:
    """Resolve the User for a request's session cookie, or None if not authenticated.

    Validates the cookie signature/age (via ``get_session_claims``), loads the
    user, and rejects cookies issued before the user's last password change
    (``_session_after_password_change``). Shared by ``require_auth`` and the login
    page so both agree on what a valid session is — a signature-valid but
    DB-stale cookie must not pass one gate and fail the other (that produces the
    /login ⇄ / redirect loop, #73).
    """
    claims = get_session_claims(request)
    if claims is None:
        return None
    username, issued_at = claims
    user = (await session.exec(select(User).where(User.username == username))).first()
    if user is None or not _session_after_password_change(user, issued_at):
        return None
    if not _session_within_sso_max_age(user, issued_at):
        return None
    return user


async def require_auth(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """FastAPI dependency — returns the authenticated User or redirects to /login."""
    user = await authenticate_session(request, session)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


async def require_api_auth(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """FastAPI dependency for /api/* routes.

    Tries Bearer token first, then session cookie. Always returns a User or
    raises HTTPException(401) — never redirects.
    """
    from app.models import ApiKey

    scheme, raw_key = get_authorization_scheme_param(request.headers.get("Authorization", ""))
    if scheme.lower() == "bearer" and raw_key:
        key_hash = hash_api_key(raw_key)
        api_key = (await session.exec(select(ApiKey).where(ApiKey.key_hash == key_hash))).first()
        if api_key is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if api_key.readonly and request.method not in ("GET", "HEAD"):
            raise HTTPException(status_code=403, detail="Read-only API key")
        user_id = api_key.user_id  # capture before commit expires the object
        # Throttle the last_used_at write: a commit per request (including read-only
        # GETs) is a wasted write that contends with the scheduler under load. Only
        # write when the recorded value is missing or older than the configured window.
        now = datetime.now(timezone.utc)
        last_used = api_key.last_used_at
        if last_used is not None and last_used.tzinfo is None:
            last_used = last_used.replace(tzinfo=timezone.utc)
        if last_used is None or (now - last_used).total_seconds() >= settings.api_key_last_used_throttle_seconds:
            api_key.last_used_at = now
            session.add(api_key)
            await session.commit()
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return user

    # Fall back to session cookie
    user = await authenticate_session(request, session)
    if user is not None:
        return user

    raise HTTPException(status_code=401, detail="Authentication required")


async def require_admin(current_user: Annotated[User, Depends(require_api_auth)]):
    """FastAPI dependency for JSON API routes — requires admin, raises 401/403."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_admin_ui(current_user: Annotated[User, Depends(require_auth)]):
    """FastAPI dependency for HTML admin routes — redirect semantics, not JSON errors.

    Built on ``require_auth`` so an expired/absent session redirects to /login (303)
    like every other UI route, and a non-admin is bounced to the dashboard instead
    of receiving a raw JSON 403 (M2 / #7).
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=303, headers={"Location": "/"})
    return current_user


def set_session(response, username: str, *, max_age: int | None = None) -> None:
    # CSRF stance (#16): protection is SameSite=Lax (+ Secure in prod), not tokens.
    # This is a deliberate decision, not an oversight — see the CSRF note in
    # CLAUDE.md. SameSite=Lax stops cross-site cookies on unsafe top-level
    # navigations and all sub-resource requests; the JSON API additionally rejects
    # cross-origin form posts because it requires an application/json body and
    # supports a Bearer token as the primary M2M credential. If a cookie-authed
    # state-changing browser flow ever needs stronger defense-in-depth, add
    # per-request CSRF tokens here + a matching hidden field in the templates.
    # max_age overrides the default for SSO logins (the shorter oidc_session_max_age,
    # #221); the server-side age check in authenticate_session is authoritative.
    response.set_cookie(
        key=settings.session_cookie_name,
        value=create_session_cookie(username),
        max_age=settings.session_max_age if max_age is None else max_age,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
    )


def clear_session(response) -> None:
    response.delete_cookie(key=settings.session_cookie_name)


def set_oidc_id_token(response, id_token: str, *, max_age: int) -> None:
    """Persist the IdP's id_token (HttpOnly) as the id_token_hint for RP-initiated
    logout (#221). Only the user's own token; never logged, never read by JS."""
    response.set_cookie(
        key=settings.oidc_id_token_cookie_name,
        value=id_token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
    )


def get_oidc_id_token(request: Request) -> str | None:
    return request.cookies.get(settings.oidc_id_token_cookie_name)


def clear_oidc_id_token(response) -> None:
    response.delete_cookie(key=settings.oidc_id_token_cookie_name)


async def seed_admin() -> None:
    """Create the initial admin user from env vars if no users exist."""

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
