"""Regression tests for the low-priority code-review fixes.

D4 #14 (shared bcrypt rounds), #17 (defensive JSON parsing), #18 (_looks_generic
false positives).
"""

import bcrypt
import pytest

from app.auth import _DUMMY_HASH, BCRYPT_ROUNDS, hash_password
from app.routes.api import ExtensionOut
from app.scoring import _looks_generic

# ───────────────────────── D4 #14 — bcrypt rounds ─────────────────────────


def _rounds(bcrypt_hash: str) -> int:
    # bcrypt hash format: $2b$<rounds>$<salt+digest>
    return int(bcrypt_hash.split("$")[2])


def test_dummy_hash_uses_shared_rounds():
    assert _rounds(_DUMMY_HASH) == BCRYPT_ROUNDS


async def test_real_hash_uses_shared_rounds():
    hashed = await hash_password("whatever-password")
    assert _rounds(hashed) == BCRYPT_ROUNDS


def test_dummy_and_real_rounds_match():
    """The whole point of D4: the timing-defense and real hashing can't drift."""
    real = bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    assert _rounds(_DUMMY_HASH) == _rounds(real)


# ───────────────────────── #17 — defensive JSON parsing ─────────────────────────


def _ext(**kw):
    from app.models import Extension

    defaults = dict(
        id=1,
        store="chrome",
        extension_id="a" * 32,
        name="E",
        publisher="P",
        version="1",
        store_url="https://x",
        permissions="[]",
        risk_score=10,
    )
    defaults.update(kw)
    return Extension(**defaults)


def test_from_db_survives_malformed_json():
    ext = _ext(
        permissions="{not valid json",
        risk_detail="also not json",
        package_analysis="{broken",
    )
    out = ExtensionOut.from_db(ext)  # must not raise
    assert out.permissions == []
    assert out.host_permissions == []
    assert out.findings == []
    assert out.risk_detail is None


def test_from_db_parses_valid_json():
    ext = _ext(permissions='["storage", "tabs"]', risk_detail='{"total": 10}')
    out = ExtensionOut.from_db(ext)
    assert out.permissions == ["storage", "tabs"]
    assert out.risk_detail == {"total": 10}


# ───────────────────────── #18 — _looks_generic false positives ─────────────────────────


@pytest.mark.parametrize(
    "publisher",
    [
        "Microsoft Extensions",  # distinctive word "microsoft" → not generic
        "Acme Tools Inc",  # corporate suffix stripped, "acme" remains
        "JetBrains s.r.o.",
        "Toolsmith Software",  # "tools" only as a substring, not a whole word
        "Browser Plugins",  # "browser" is distinctive
        "Google",
    ],
)
def test_legitimate_publishers_not_generic(publisher):
    assert _looks_generic(publisher) is False


@pytest.mark.parametrize(
    "publisher",
    [
        "",  # empty
        "Extensions",  # purely a generic word
        "Tools",
        "ExtensionTools",  # CamelCase concatenation of two generic words
        "12345",  # no letters
        "Tools Inc",  # only a generic word + corporate suffix
    ],
)
def test_generic_publishers_flagged(publisher):
    assert _looks_generic(publisher) is True
