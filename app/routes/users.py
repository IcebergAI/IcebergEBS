from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, update as sa_update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import clear_session, hash_password, verify_password, require_admin, require_api_auth
from app.database import get_session
from app.models import AlertDestination, AlertLog, AlertRule, ApiKey, Extension, User

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

    # Preserve history rather than hard-cascading owned data — mirror how
    # delete_rule / delete_destination keep AlertLog rows and only sever the FKs
    # to the rows being removed (#28). The forensic trail (alert log + each
    # extension's fetch/install history) survives an account deletion.
    rule_ids = (await session.exec(
        select(AlertRule.id).where(AlertRule.user_id == user_id)
    )).all()
    dest_ids = (await session.exec(
        select(AlertDestination.id).where(AlertDestination.user_id == user_id)
    )).all()

    # Null the AlertLog FKs that point at the user/rules/destinations we delete,
    # leaving the log rows (and their still-valid extension_id) intact. The
    # extension FK stays valid because we orphan extensions below rather than
    # deleting them — a dangling FK would raise IntegrityError on Postgres.
    await session.execute(
        sa_update(AlertLog).where(AlertLog.user_id == user_id).values(user_id=None)
    )
    if rule_ids:
        await session.execute(
            sa_update(AlertLog).where(AlertLog.rule_id.in_(rule_ids)).values(rule_id=None)
        )
    if dest_ids:
        await session.execute(
            sa_update(AlertLog).where(AlertLog.destination_id.in_(dest_ids)).values(destination_id=None)
        )

    # Remove the user's own config rows (rules, destinations, API keys).
    await session.execute(sa_delete(AlertRule).where(AlertRule.user_id == user_id))
    await session.execute(sa_delete(AlertDestination).where(AlertDestination.user_id == user_id))
    await session.execute(sa_delete(ApiKey).where(ApiKey.user_id == user_id))

    # Orphan the user's extensions (and, transitively, their FetchLog /
    # InstallCountHistory / AlertLog) instead of deleting them: null the owner and
    # drop them off the watchlist so the scheduler stops refreshing unowned rows.
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
