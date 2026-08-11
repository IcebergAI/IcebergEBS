"""Explain newly introduced risky package capabilities between snapshots."""


def _strings(value: object) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _finding_key(finding: object) -> tuple[object, ...] | None:
    if not isinstance(finding, dict):
        return None
    fields = ("code", "severity", "title", "detail", "source", "file", "line")
    values = tuple(finding.get(field) for field in fields)
    return values if all(isinstance(value, (str, int, type(None))) for value in values) else None


def _new_findings(old: object, new: object) -> list[dict[str, object]]:
    old_keys = {_finding_key(item) for item in old} if isinstance(old, list) else set()
    result: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    if not isinstance(new, list):
        return result
    for item in new:
        key = _finding_key(item)
        if key is not None and key not in old_keys and key not in seen and isinstance(item, dict):
            result.append({key: value for key, value in item.items() if isinstance(key, str)})
            seen.add(key)
    return result


def diff_analysis(old: dict[str, object], new: dict[str, object]) -> dict[str, object] | None:
    """Return only added security-relevant behavior, or ``None`` when unchanged.

    Snapshots are historical data and may be damaged or produced by an older
    inspector version, so every field is shape-checked and removals never alert.
    """
    added_permissions = sorted(
        (_strings(new.get("permissions")) | _strings(new.get("host_permissions")))
        - (_strings(old.get("permissions")) | _strings(old.get("host_permissions")))
    )
    added_domains = sorted(_strings(new.get("external_domains")) - _strings(old.get("external_domains")))
    findings = _new_findings(old.get("findings"), new.get("findings"))
    remote_code_enabled = not bool(old.get("uses_remote_code")) and bool(new.get("uses_remote_code"))
    result: dict[str, object] = {}
    if added_permissions:
        result["added_permissions"] = added_permissions
    if remote_code_enabled:
        result["remote_code_enabled"] = True
    if added_domains:
        result["added_domains"] = added_domains
    if findings:
        result["new_findings"] = findings
    return result or None
