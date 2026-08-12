"""Secure retrieval of an operator-configured threat feed."""

import json
from urllib.parse import urlparse

import httpx

from app.threats import ThreatEntryInput, parse_feed_payload
from app.webhooks import _authority, validate_webhook_url

MAX_FEED_BYTES = 2 * 1024 * 1024


async def fetch_threat_feed(
    client: httpx.AsyncClient,
    url: str,
    *,
    default_source: str,
) -> list[ThreatEntryInput]:
    """Fetch a JSON feed over a validated, DNS-pinned HTTPS request.

    Redirects are disabled and the URL is resolved immediately before the
    request, mirroring alert webhook SSRF controls. The feed is operator
    configured, but it is still untrusted input and must not reach private IPs.
    """
    ips = await validate_webhook_url(url)
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("threat feed URL has no host")
    pinned = parsed._replace(netloc=_authority(ips[0], parsed.port)).geturl()
    chunks: list[bytes] = []
    total = 0
    async with client.stream(
        "GET",
        pinned,
        headers={"Host": _authority(host, parsed.port), "Accept": "application/json"},
        follow_redirects=False,
        extensions={"sni_hostname": host} if parsed.scheme == "https" else {},
    ) as response:
        response.raise_for_status()
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_FEED_BYTES:
                raise ValueError(f"threat feed response exceeds the {MAX_FEED_BYTES}-byte limit")
            chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks))
    except json.JSONDecodeError as exc:
        raise ValueError("threat feed response is not valid JSON") from exc
    return parse_feed_payload(payload, default_source=default_source)
