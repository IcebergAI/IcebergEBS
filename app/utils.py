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
#
# include_psl_private_domains=True honours the PSL *private* section (github.io,
# blogspot.com, s3-style buckets, …) so independently-controlled tenants under a
# hosting suffix — alice.github.io vs bob.github.io — count as distinct parties
# rather than both collapsing to github.io, which is exactly the undercount this
# score guards against (#254 review).
_psl_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


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


def host_permissions_of(analysis: dict | None) -> list[str]:
    """Host permissions from an already-parsed ``package_analysis`` dict; [] when the
    analysis is missing, ``host_permissions`` is not a list, or its members aren't strings.

    The single shape guard for this field (#291), taking the parsed dict so a caller that
    already has it (the JSON DTO, the detail page) doesn't re-parse the multi-KB blob;
    ``Extension.host_permissions_list()`` wraps it for callers that only have the row."""
    if analysis is None:
        return []
    hosts = analysis.get("host_permissions", [])
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, str)]


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
    # top_domain_under_public_suffix is the non-deprecated spelling of the old
    # registered_domain, and (with private domains enabled above) is private-suffix
    # aware — the eTLD+1 under the full public suffix.
    return _psl_extract(hostname).top_domain_under_public_suffix or hostname
