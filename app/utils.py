from urllib.parse import urlparse


def domain_from_url(url: str) -> str:
    """Return the hostname from a URL, or empty string if none or no dot."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return hostname if "." in hostname else ""
