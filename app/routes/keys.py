from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import select

from app.auth import generate_api_key, hash_api_key
from app.deps import CurrentUser, SessionDep
from app.models import ApiKey

router = APIRouter(prefix="/api", tags=["api-keys"])


class ApiKeyOut(BaseModel):
    id: int
    label: str
    key_prefix: str
    key_suffix: str
    readonly: bool
    created_at: datetime
    last_used_at: Optional[datetime]


class ApiKeyCreateIn(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    readonly: bool = False


class ApiKeyCreateOut(ApiKeyOut):
    raw_key: str  # returned once at creation time only


@router.get("/keys")
async def list_keys(
    current_user: CurrentUser,
    session: SessionDep,
) -> list[ApiKeyOut]:
    keys = (
        await session.exec(select(ApiKey).where(ApiKey.user_id == current_user.id).order_by(ApiKey.created_at))
    ).all()
    return [
        ApiKeyOut(
            id=k.id,
            label=k.label,
            key_prefix=k.key_prefix,
            key_suffix=k.key_suffix,
            readonly=k.readonly,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.post("/keys", status_code=201)
async def create_key(
    body: ApiKeyCreateIn,
    current_user: CurrentUser,
    session: SessionDep,
) -> ApiKeyCreateOut:
    raw_key = generate_api_key()
    key_prefix = raw_key[:12]
    key_suffix = raw_key[-4:]
    api_key = ApiKey(
        user_id=current_user.id,
        label=body.label,
        readonly=body.readonly,
        key_hash=hash_api_key(raw_key),
        key_prefix=key_prefix,
        key_suffix=key_suffix,
    )
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)
    return ApiKeyCreateOut(
        id=api_key.id,
        label=api_key.label,
        key_prefix=api_key.key_prefix,
        key_suffix=api_key.key_suffix,
        readonly=api_key.readonly,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        raw_key=raw_key,
    )


@router.delete("/keys/{key_id}")
async def revoke_key(
    key_id: int,
    current_user: CurrentUser,
    session: SessionDep,
):
    api_key = await session.get(ApiKey, key_id)
    if not api_key or api_key.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    await session.delete(api_key)
    await session.commit()
    return {"ok": True}
