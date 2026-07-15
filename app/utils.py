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


def domain_from_url(url: str) -> str:
    """Return the hostname from a URL, or empty string if none or no dot."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return hostname if "." in hostname else ""
