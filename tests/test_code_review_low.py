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


# ───────────────── #291 — wrong-shape stored host_permissions / risk_detail ─────────────────


@pytest.mark.parametrize(
    "stored,expected",
    [
        ('{"host_permissions": ["https://a/*", "https://b/*"]}', ["https://a/*", "https://b/*"]),
        ('{"host_permissions": "https://a/*"}', []),  # a string would iterate char-by-char
        ('{"host_permissions": {"not": "a list"}}', []),  # non-iterable → would 500 a consumer
        ('{"host_permissions": ["ok", {"bad": 1}, 7]}', ["ok"]),  # drop non-string members
        ("{}", []),  # key absent
        ("{not json", []),  # unparsable analysis
        (None, []),  # no analysis at all
    ],
)
def test_host_permissions_list_shape_guard(stored, expected):
    # The single accessor guards every consumer (scorer, notifications diff, JSON DTO,
    # detail page) against a wrong-shaped stored host_permissions (#291).
    assert _ext(package_analysis=stored).host_permissions_list() == expected


def test_effective_values_ignores_string_host_permissions():
    # The keep-stale scoring path (#142) reads stored host_permissions when no fresh
    # analysis is present. A stored string must not iterate char-by-char into
    # score_permissions' set() and silently maim the score (#291).
    from app.fetchers.base import ExtensionMetadata
    from app.scoring import score_permissions
    from app.services import _effective_values

    ext = _ext(
        permissions='["storage"]',
        # A string spelling of "<all_urls>" — char iteration would inject 'a','l','u',… as
        # bogus permissions, and could even collide with a real permission letter.
        package_analysis='{"host_permissions": "<all_urls>"}',
        last_fetched_at=None,
    )
    metadata = ExtensionMetadata(name="E", publisher="P", version="1", store_url="https://x")
    ev = _effective_values(ext, metadata, analysis=None)
    assert ev.host_permissions == []
    # storage alone is MEDIUM (7), not maxed — proves no critical leaked in via char-iteration.
    assert score_permissions(ev.permissions, ev.host_permissions) == 7


def test_risk_detail_stored_defaults_backfills_missing_keys():
    # json_object guards dict-ness but not keys; a partial write missing `total` would
    # render blank (or 500 on arithmetic) in the detail breakdown. stored_defaults()
    # backfills every RiskDetail field, derived from _fields so it can't drift (#291).
    from app.scoring import RiskDetail

    defaults = RiskDetail.stored_defaults()
    assert set(defaults) == set(RiskDetail._fields)
    assert defaults["total"] == 0 and defaults["permissions"] == 0
    assert defaults["risk_level"] == "unknown"
