"""Typed accessors for the JSON-in-str Extension columns (#167).

Each accessor owns the single defensive parse the consumers used to hand-roll,
so missing / unparsable (#17) / valid-but-wrong-shape (#61/#150) stored JSON
yields a safe fallback instead of raising at the call site.
"""

from app.models import Extension


def _ext(**kw) -> Extension:
    return Extension(
        store="chrome",
        extension_id="abcdefghijklmnopabcdefghijklmnop",
        name="X",
        publisher="",
        version="",
        store_url="https://example.com",
        **kw,
    )


# --- permissions_list -------------------------------------------------------


def test_permissions_list_parses_valid():
    assert _ext(permissions='["storage", "tabs"]').permissions_list() == ["storage", "tabs"]


def test_permissions_list_default_empty():
    assert _ext().permissions_list() == []  # column default "[]"


def test_permissions_list_unparsable_falls_back():
    assert _ext(permissions="{not json").permissions_list() == []


def test_permissions_list_wrong_shape_falls_back():
    # Valid JSON, wrong container (object, not array) → [] rather than a dict.
    assert _ext(permissions='{"a": 1}').permissions_list() == []


def test_permissions_list_drops_non_string_members():
    # A wrong-typed member would 500 the list[str] DTO / the export join — drop it (#150).
    assert _ext(permissions='["tabs", 5, null, {"x": 1}, "storage"]').permissions_list() == ["tabs", "storage"]


# --- analysis_dict ----------------------------------------------------------


def test_analysis_dict_parses_valid():
    assert _ext(package_analysis='{"host_permissions": ["<all_urls>"]}').analysis_dict() == {
        "host_permissions": ["<all_urls>"]
    }


def test_analysis_dict_absent_is_none():
    assert _ext().analysis_dict() is None


def test_analysis_dict_unparsable_is_none():
    assert _ext(package_analysis="{bad").analysis_dict() is None


def test_analysis_dict_wrong_shape_is_none():
    # A JSON array where an object is expected → None (would have AttributeError'd on .get, #150).
    assert _ext(package_analysis="[1, 2, 3]").analysis_dict() is None


# --- risk_detail_dict -------------------------------------------------------


def test_risk_detail_dict_parses_valid():
    assert _ext(risk_detail='{"total": 42}').risk_detail_dict() == {"total": 42}


def test_risk_detail_dict_absent_is_none():
    assert _ext().risk_detail_dict() is None


def test_risk_detail_dict_wrong_shape_is_none():
    assert _ext(risk_detail='"a string"').risk_detail_dict() is None
