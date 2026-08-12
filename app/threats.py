"""Threat-list input validation and feed parsing.

Threat-list entries are deliberately fail-closed: a feed may add entries, but it
never removes one implicitly.  The database is the durable source of truth and
the scoring/alert pipeline applies every stored match.
"""

from dataclasses import dataclass
from urllib.parse import urlparse

SUPPORTED_STORES = frozenset({"chrome", "vscode", "edge"})
MAX_EXTENSION_ID_LENGTH = 512
MAX_SOURCE_LENGTH = 128
MAX_REASON_LENGTH = 1000
MAX_FEED_ENTRIES = 1000


@dataclass(frozen=True)
class ThreatEntryInput:
    store: str
    extension_id: str
    source: str
    reason: str | None = None


def normalize_entry(
    store: str,
    extension_id: str,
    source: str,
    reason: str | None = None,
) -> ThreatEntryInput:
    """Normalize and bound one threat-list entry.

    Store identifiers are intentionally exact after lower-casing; callers that
    accept store URLs normalize those through the existing API helper first.
    """
    normalized_store = store.strip().lower()
    normalized_id = extension_id.strip()
    normalized_source = source.strip()
    normalized_reason = reason.strip() if reason is not None else None
    if normalized_store not in SUPPORTED_STORES:
        raise ValueError(f"store must be one of: {', '.join(sorted(SUPPORTED_STORES))}")
    if not normalized_id or len(normalized_id) > MAX_EXTENSION_ID_LENGTH:
        raise ValueError("extension_id must be present and within the supported length")
    if not normalized_source or len(normalized_source) > MAX_SOURCE_LENGTH:
        raise ValueError("source must be present and within the supported length")
    if normalized_reason is not None and len(normalized_reason) > MAX_REASON_LENGTH:
        raise ValueError("reason exceeds the supported length")
    return ThreatEntryInput(normalized_store, normalized_id, normalized_source, normalized_reason or None)


def parse_feed_payload(payload: object, *, default_source: str) -> list[ThreatEntryInput]:
    """Parse a feed response.

    Accept either a bare JSON array or ``{"entries": [...]}``.  Invalid rows
    fail the whole pull rather than silently accepting a partial, ambiguous
    feed.  A feed source may be supplied per row; otherwise the configured
    source name is used.
    """
    rows: object = payload.get("entries") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("threat feed must be a JSON array or an object with an entries array")
    if len(rows) > MAX_FEED_ENTRIES:
        raise ValueError(f"threat feed exceeds the {MAX_FEED_ENTRIES}-entry limit")
    entries: list[ThreatEntryInput] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("every threat feed entry must be an object")
        source = row.get("source", default_source)
        reason = row.get("reason")
        if not isinstance(row.get("store"), str) or not isinstance(row.get("extension_id"), str):
            raise ValueError("every threat feed entry needs string store and extension_id")
        if not isinstance(source, str) or (reason is not None and not isinstance(reason, str)):
            raise ValueError("threat feed source and reason must be strings")
        entry = normalize_entry(row["store"], row["extension_id"], source, reason)
        identity = (entry.store, entry.extension_id, entry.source)
        if identity not in seen:
            seen.add(identity)
            entries.append(entry)
    return entries


def validate_feed_url(value: str) -> str:
    """Require an operator-supplied HTTPS feed URL without embedded secrets."""
    if not value:
        return value
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("threat_feed_url must be an HTTPS URL without embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("threat_feed_url must not contain a query string or fragment")
    return value.rstrip("/")


def finding_for_entries(entries: list[ThreatEntryInput]) -> dict[str, str]:
    """Return the stable synthetic finding shown for a known-bad match."""
    details = "; ".join(f"{entry.source}: {entry.reason}" if entry.reason else entry.source for entry in entries)
    return {
        "code": "threat_match",
        "severity": "critical",
        "title": "Known-bad extension matched a threat list",
        "detail": details[:MAX_REASON_LENGTH],
        "source": "threat_list",
    }
