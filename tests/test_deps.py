"""Unit tests for the shared owner-scoped fetch gate get_owned_or_404 (#169).

Consolidates the ownership 404 gate that was repeated ~12× across the JSON API
routes. The end-to-end route tests cover the wiring; these pin the helper's
contract directly — importantly that a missing row and another user's row are
indistinguishable (both 404) so ownership can't be probed.
"""

import pytest
from fastapi import HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from app.deps import get_owned_or_404
from app.models import Extension


async def _make_ext(session, user_id) -> int:
    ext = Extension(
        user_id=user_id,
        store="chrome",
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="Ext",
        publisher="",
        version="",
        store_url="https://example.com",
        permissions="[]",
    )
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ext.id


async def test_returns_row_for_owner(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        ext_id = await _make_ext(s, admin_user.id)
        obj = await get_owned_or_404(s, Extension, ext_id, admin_user.id)
        assert obj.id == ext_id


async def test_404_for_missing_row(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        with pytest.raises(HTTPException) as exc:
            await get_owned_or_404(s, Extension, 999_999, admin_user.id)
        assert exc.value.status_code == 404


async def test_404_for_another_users_row_is_indistinguishable_from_missing(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        ext_id = await _make_ext(s, admin_user.id)
        with pytest.raises(HTTPException) as exc:
            await get_owned_or_404(s, Extension, ext_id, admin_user.id + 12_345)
        # Same 404 (and default detail) as a missing row — ownership can't be probed.
        assert exc.value.status_code == 404
        assert exc.value.detail == "Not found"


async def test_custom_detail_propagates(test_db, admin_user):
    async with AsyncSession(test_db) as s:
        with pytest.raises(HTTPException) as exc:
            await get_owned_or_404(s, Extension, 999_999, admin_user.id, detail="Destination not found")
        assert exc.value.detail == "Destination not found"
