import json
import logging
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)

# Public Suffix List matcher pinned to tldextract's bundled snapshot:
# suffix_list_urls=() disables the default network fetch of a fresh PSL and
# cache_dir=None disables its disk cache, so this never touches the network or
# filesystem — a hard requirement for an SSRF-conscious app whose containers
# must not grow surprise egress at import time. The snapshot refreshes with the
# (Dependabot-managed) tldextract release cadence, which is plenty for scoring.
_psl_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


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


def registrable_domain(hostname: str) -> str:
    """Collapse a hostname to its registrable domain (eTLD+1) via the Public
    Suffix List: api.evil.com and cdn.evil.com both → evil.com, while
    foo.co.uk stays foo.co.uk (string logic can't tell co.uk from evil.com).

    Falls back to the hostname itself when the PSL yields no registrable domain
    (IP literals, single-label hosts, unknown suffixes) so callers never lose an
    entry by normalising it.
    """
    return _psl_extract(hostname).registered_domain or hostname
