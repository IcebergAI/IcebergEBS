from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import clear_session, hash_password, verify_password, require_admin, require_api_auth
from app.database import get_session
from app.models import AlertDestination, AlertLog, AlertRule, ApiKey, Extension, FetchLog, InstallCountHistory, User

router = APIRouter()


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


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    users = (await session.exec(select(User).order_by(User.created_at))).all()
    return [UserOut(id=u.id, username=u.username, email=u.email, is_admin=u.is_admin) for u in users]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: CreateUserIn,
    _: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
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
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    target = await session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Collect the user's extension and rule ids so child rows can be removed in
    # bulk (and in FK-safe order) rather than row-by-row.
    ext_ids = (await session.exec(
        select(Extension.id).where(Extension.user_id == user_id)
    )).all()
    rule_ids = (await session.exec(
        select(AlertRule.id).where(AlertRule.user_id == user_id)
    )).all()

    # AlertLog rows owned by this user — directly (user_id), via one of their
    # extensions, or via one of their rules (covers legacy logs with a null user_id).
    log_conditions = [AlertLog.user_id == user_id]
    if ext_ids:
        log_conditions.append(AlertLog.extension_id.in_(ext_ids))
    if rule_ids:
        log_conditions.append(AlertLog.rule_id.in_(rule_ids))
    await session.execute(sa_delete(AlertLog).where(or_(*log_conditions)))

    # Rules and destinations next (referenced by logs, reference extensions/user).
    await session.execute(sa_delete(AlertRule).where(AlertRule.user_id == user_id))
    await session.execute(sa_delete(AlertDestination).where(AlertDestination.user_id == user_id))

    if ext_ids:
        await session.execute(sa_delete(FetchLog).where(FetchLog.extension_id.in_(ext_ids)))
        await session.execute(sa_delete(InstallCountHistory).where(InstallCountHistory.extension_id.in_(ext_ids)))

    await session.execute(sa_delete(ApiKey).where(ApiKey.user_id == user_id))
    await session.execute(sa_delete(Extension).where(Extension.user_id == user_id))

    await session.delete(target)
    await session.commit()
    return {"ok": True}


@router.patch("/users/me/password")
async def change_password(
    body: ChangePasswordIn,
    response: Response,
    current_user: Annotated[User, Depends(require_api_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
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
