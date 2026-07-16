import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def safe_json_loads(raw: str | None, default: str, field: str, ext_id: int | None):
    """json.loads with a fallback: malformed stored JSON logs a warning instead of
    raising and 500-ing the endpoint (#17)."""
    try:
        return json.loads(raw or default)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Malformed %s JSON for extension %s — using fallback", field, ext_id)
        return json.loads(default)


def json_list(raw: str | None, field: str, ext_id: int | None) -> list:
    """Parse a stored JSON array. Returns [] on missing, unparsable (#17), or
    valid-but-wrong-shape (#61/#150) JSON — the single defensive parse the
    Extension accessor methods delegate to (#167)."""
    value = safe_json_loads(raw, "[]", field, ext_id)
    if isinstance(value, list):
        return value
    logger.warning("Expected a JSON array for %s of extension %s — using fallback", field, ext_id)
    return []


def json_object(raw: str | None, field: str, ext_id: int | None) -> dict | None:
    """Parse a stored JSON object. Returns None when absent, and also — rather than
    the wrong-typed value that would later AttributeError on ``.get`` (#61/#150) —
    when the stored JSON is unparsable or not an object (#167)."""
    value = safe_json_loads(raw, "null", field, ext_id)
    if isinstance(value, dict):
        return value
    if value is not None:
        logger.warning("Expected a JSON object for %s of extension %s — using fallback", field, ext_id)
    return None


def domain_from_url(url: str) -> str:
    """Return the hostname from a URL, or empty string if none or no dot."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return hostname if "." in hostname else ""
