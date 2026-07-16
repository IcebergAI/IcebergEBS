"""Unit tests for the findings-grouping algorithm (#170).

Extracted from routes/ui.py, where it could only be exercised through a full
page render. These drive group_detection_findings directly and cover the
four-branch section-shaping conditional plus grouping, dedupe, and the
skip-non-dict guard.
"""

from app.findings_view import group_detection_findings


def _f(**kw) -> dict:
    base = {
        "severity": "high",
        "source": "package",
        "code": "c",
        "title": "T",
        "detail": "",
        "file": None,
        "line": None,
    }
    base.update(kw)
    return base


def test_skips_non_dict_findings():
    groups = group_detection_findings([_f(detail="d"), "not a dict", 123, None])
    assert len(groups) == 1


def test_groups_by_severity_source_code_title():
    groups = group_detection_findings([_f(code="a"), _f(code="b")])
    assert len(groups) == 2
    assert {g["code"] for g in groups} == {"a", "b"}


def test_dedupes_identical_location_and_detail():
    groups = group_detection_findings([_f(file="a.js", line=1, detail="boom"), _f(file="a.js", line=1, detail="boom")])
    assert len(groups) == 1
    # a single deduped row → single-detail shape with one location
    assert groups[0]["sections"] == [{"type": "detail", "detail": "boom", "locations": ["a.js:1"]}]
    assert groups[0]["row_label"] == "locations"


def test_single_detail_many_locations_shape():
    groups = group_detection_findings([_f(file="a.js", line=1, detail="boom"), _f(file="b.js", line=2, detail="boom")])
    (g,) = groups
    assert g["row_label"] == "locations"
    assert g["sections"] == [{"type": "detail", "detail": "boom", "locations": ["a.js:1", "b.js:2"]}]


def test_single_location_many_details_shape():
    groups = group_detection_findings([_f(file="a.js", line=1, detail="d1"), _f(file="a.js", line=1, detail="d2")])
    (g,) = groups
    assert g["row_label"] == "findings"
    assert g["sections"] == [{"type": "location", "location": "a.js:1", "details": ["d1", "d2"]}]


def test_details_fewer_than_locations_groups_per_detail():
    groups = group_detection_findings(
        [
            _f(file="a.js", line=1, detail="d1"),
            _f(file="a.js", line=2, detail="d1"),
            _f(file="b.js", line=1, detail="d2"),
        ]
    )
    (g,) = groups
    assert g["row_label"] == "entries"
    assert g["sections"] == [
        {"type": "detail", "detail": "d1", "locations": ["a.js:1", "a.js:2"]},
        {"type": "detail", "detail": "d2", "locations": ["b.js:1"]},
    ]


def test_locations_fewer_than_details_groups_per_location():
    groups = group_detection_findings(
        [
            _f(file="a.js", line=1, detail="d1"),
            _f(file="a.js", line=1, detail="d2"),
            _f(file="b.js", line=1, detail="d3"),
        ]
    )
    (g,) = groups
    assert g["row_label"] == "entries"
    assert g["sections"] == [
        {"type": "location", "location": "a.js:1", "details": ["d1", "d2"]},
        {"type": "location", "location": "b.js:1", "details": ["d3"]},
    ]


def test_location_equal_to_source_is_blanked():
    # No file → location falls back to source ("package"); in a single-location
    # section that matches the source, it's blanked so the template omits it.
    groups = group_detection_findings([_f(detail="d1"), _f(detail="d2")])
    (g,) = groups
    assert g["sections"] == [{"type": "location", "location": "", "details": ["d1", "d2"]}]


def test_location_without_line_uses_file_only():
    groups = group_detection_findings([_f(file="manifest.json", line=None, detail="boom")])
    (g,) = groups
    assert g["sections"] == [{"type": "detail", "detail": "boom", "locations": ["manifest.json"]}]


def test_defaults_for_missing_fields():
    # Missing severity/source/code/title fall back to their defaults.
    groups = group_detection_findings([{"detail": "x"}])
    (g,) = groups
    assert g["severity"] == "low"
    assert g["source"] == "package"
    assert g["title"] == "Detection finding"
    # internal bookkeeping is stripped before returning
    assert "_seen_rows" not in g
