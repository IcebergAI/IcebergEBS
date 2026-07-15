"""Regression tests for #67: secret_key min-length + bcrypt 72-byte truncation."""

import pytest
from pydantic import ValidationError

from app.auth import (
    MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    _hash_password_sync,
    _verify_password_sync,
    hash_password,
    verify_password,
)
from app.config import _MIN_SECRET_KEY_LENGTH, Settings


def test_secret_key_below_minimum_is_rejected():
    with pytest.raises(ValidationError):
        Settings(
            admin_username="admin",
            admin_password="pw",
            secret_key="x" * (_MIN_SECRET_KEY_LENGTH - 1),
        )


def test_secret_key_at_minimum_is_accepted():
    s = Settings(
        admin_username="admin",
        admin_password="pw",
        secret_key="x" * _MIN_SECRET_KEY_LENGTH,
    )
    assert len(s.secret_key.get_secret_value()) == _MIN_SECRET_KEY_LENGTH


def test_password_over_72_bytes_is_rejected_not_truncated():
    # Two passwords identical for their first 72 bytes but differing after. Under
    # bcrypt's raw 72-byte ceiling these would hash to the same value; #67 rejects
    # them explicitly instead, so the silent collision cannot happen.
    prefix = "a" * MAX_PASSWORD_BYTES
    with pytest.raises(PasswordTooLongError):
        _hash_password_sync(prefix + "-alpha")
    with pytest.raises(PasswordTooLongError):
        _hash_password_sync(prefix + "-omega")


def test_password_at_limit_is_accepted():
    at_limit = "a" * MAX_PASSWORD_BYTES
    hashed = _hash_password_sync(at_limit)
    assert _verify_password_sync(at_limit, hashed) is True
    # An over-long verify attempt can never match, and must not raise.
    assert _verify_password_sync("a" * (MAX_PASSWORD_BYTES + 50), hashed) is False


async def test_hash_verify_roundtrip():
    hashed = await hash_password("correct horse battery staple")
    assert await verify_password("correct horse battery staple", hashed) is True
    assert await verify_password("wrong password", hashed) is False
