from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlmodel import select

from app.auth import MAX_PASSWORD_BYTES, clear_session, hash_password, verify_password
from app.deps import AdminUser, CurrentUser, SessionDep
from app.models import ApiKey, Extension, User

router = APIRouter(prefix="/api", tags=["users"])


def _reject_over_long_password(v: str) -> str:
    # bcrypt hashes at most 72 bytes; reject longer here so the caller gets a clean
    # 422 rather than an over-long password being truncated or 500ing at hash time (#67).
    if len(v.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return v


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    is_admin: bool


class CreateUserIn(BaseModel):
    username: str
    password: str = Field(min_length=8)
    email: str | None = None
    is_admin: bool = False

    _check_password = field_validator("password")(_reject_over_long_password)


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)

    _check_new_password = field_validator("new_password")(_reject_over_long_password)


@router.get("/users")
async def list_users(
    _: AdminUser,
    session: SessionDep,
) -> list[UserOut]:
    users = (await session.exec(select(User).order_by(User.created_at))).all()
    return [UserOut(id=u.id, username=u.username, email=u.email, is_admin=u.is_admin) for u in users]


@router.post("/users", status_code=201)
async def create_user(
    body: CreateUserIn,
    _: AdminUser,
    session: SessionDep,
) -> UserOut:
    existing = (await session.exec(select(User).where(User.username == body.username))).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")

    user = User(
        username=body.username,
        password_hash=await hash_password(body.password),
        email=body.email,
        is_admin=body.is_admin,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return UserOut(id=user.id, username=user.username, email=user.email, is_admin=user.is_admin)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: AdminUser,
    session: SessionDep,
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    target = await session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Preserve history rather than hard-cascading owned data (#28). The user's config
    # rows (rules, destinations, API keys) are ON DELETE CASCADE; AlertLog rows keep
    # their extension_id but have user_id/rule_id/destination_id set to NULL by their
    # SET NULL FKs — so the forensic trail (alert log + each extension's fetch/install
    # history) survives the account deletion.
    #
    # Extensions are *orphaned*, not deleted: the FK alone (SET NULL) would null the
    # owner but leave them on the watchlist, so do it explicitly here — null the owner
    # and drop them off the watchlist so the scheduler stops refreshing unowned rows.
    await session.execute(
        sa_update(Extension).where(Extension.user_id == user_id).values(user_id=None, watchlist=False)
    )

    await session.delete(target)
    await session.commit()
    return {"ok": True}


@router.patch("/users/me/password")
async def change_password(
    body: ChangePasswordIn,
    response: Response,
    current_user: CurrentUser,
    session: SessionDep,
):
    if not await verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.password_hash = await hash_password(body.new_password)
    # Invalidate all existing sessions (incl. other devices) by advancing the
    # password-change marker, and revoke the user's API keys so a leaked bearer
    # token can't survive a password reset (M1 / #6).
    current_user.password_changed_at = datetime.now(timezone.utc)
    session.add(current_user)
    await session.execute(sa_delete(ApiKey).where(ApiKey.user_id == current_user.id))
    await session.commit()
    clear_session(response)
    return {"ok": True}
