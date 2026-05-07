from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import hash_password, verify_password, require_admin, require_auth
from app.database import get_session
from app.models import AlertDestination, AlertLog, AlertRule, Extension, FetchLog, InstallCountHistory, User

router = APIRouter()


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    is_admin: bool


class CreateUserIn(BaseModel):
    username: str
    password: str
    email: str | None = None
    is_admin: bool = False


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


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
        password_hash=hash_password(body.password),
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

    # Delete owned data before the user row to avoid FK violations
    extensions = (await session.exec(
        select(Extension).where(Extension.user_id == user_id)
    )).all()
    for ext in extensions:
        await session.exec(
            select(FetchLog).where(FetchLog.extension_id == ext.id)
        )
        logs = (await session.exec(select(FetchLog).where(FetchLog.extension_id == ext.id))).all()
        for log in logs:
            await session.delete(log)
        history = (await session.exec(
            select(InstallCountHistory).where(InstallCountHistory.extension_id == ext.id)
        )).all()
        for h in history:
            await session.delete(h)
        rules_for_ext = (await session.exec(
            select(AlertRule).where(AlertRule.extension_id == ext.id)
        )).all()
        for r in rules_for_ext:
            logs_for_rule = (await session.exec(
                select(AlertLog).where(AlertLog.rule_id == r.id)
            )).all()
            for al in logs_for_rule:
                await session.delete(al)
            await session.delete(r)
        await session.delete(ext)

    rules = (await session.exec(select(AlertRule).where(AlertRule.user_id == user_id))).all()
    for r in rules:
        logs_for_rule = (await session.exec(select(AlertLog).where(AlertLog.rule_id == r.id))).all()
        for al in logs_for_rule:
            await session.delete(al)
        await session.delete(r)

    dests = (await session.exec(
        select(AlertDestination).where(AlertDestination.user_id == user_id)
    )).all()
    for d in dests:
        await session.delete(d)

    await session.delete(target)
    await session.commit()
    return {"ok": True}


@router.patch("/users/me/password")
async def change_password(
    body: ChangePasswordIn,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.password_hash = hash_password(body.new_password)
    session.add(current_user)
    await session.commit()
    return {"ok": True}
