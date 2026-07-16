"""Pure presentation logic for the extension detail page's package findings.

Groups the flat ``findings`` list stored in ``package_analysis`` into the shape
the detail template renders: one group per (severity, source, code, title), with
each group's rows folded into "sections" that read naturally whether the finding
repeats across locations, across details, or both. No HTTP or DB dependency —
extracted from ``routes/ui.py`` so it is unit-testable on its own (#170).
"""


def _finding_location(finding: dict, source: str) -> str:
    file = finding.get("file")
    if file:
        line = finding.get("line")
        return f"{file}:{line}" if line is not None else str(file)
    return source


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _finding_sections(rows: list[dict], source: str) -> tuple[list[dict], str]:
    locations = _unique([row["location"] for row in rows])
    details = _unique([row["detail"] for row in rows if row["detail"]])

    if len(details) == 1:
        return (
            [
                {
                    "type": "detail",
                    "detail": details[0],
                    "locations": locations,
                }
            ],
            "locations",
        )

    if len(locations) == 1:
        return (
            [
                {
                    "type": "location",
                    "location": "" if locations[0] == source else locations[0],
                    "details": details,
                }
            ],
            "findings",
        )

    if len(details) <= len(locations):
        return (
            [
                {
                    "type": "detail",
                    "detail": detail,
                    "locations": _unique([row["location"] for row in rows if row["detail"] == detail]),
                }
                for detail in details
            ],
            "entries",
        )

    return (
        [
            {
                "type": "location",
                "location": "" if location == source else location,
                "details": _unique([row["detail"] for row in rows if row["location"] == location and row["detail"]]),
            }
            for location in locations
        ],
        "entries",
    )


def group_detection_findings(findings: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str, str], dict] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = finding.get("severity") or "low"
        source = finding.get("source") or "package"
        code = finding.get("code") or ""
        title = finding.get("title") or code or "Detection finding"
        detail = finding.get("detail") or ""
        key = (severity, source, code, title)

        group = grouped.setdefault(
            key,
            {
                "code": code,
                "severity": severity,
                "title": title,
                "source": source,
                "rows": [],
                "_seen_rows": set(),
            },
        )

        location = _finding_location(finding, source)
        row_key = (location, detail)
        if row_key in group["_seen_rows"]:
            continue
        group["_seen_rows"].add(row_key)
        group["rows"].append(
            {
                "location": location,
                "detail": detail,
            }
        )

    for group in grouped.values():
        group["sections"], group["row_label"] = _finding_sections(group["rows"], group["source"])
        del group["_seen_rows"]
    return list(grouped.values())
