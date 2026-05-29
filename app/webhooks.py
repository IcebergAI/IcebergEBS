import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_BLOCKED_HOSTNAMES = frozenset({"localhost", "localtest.me"})
_WEBHOOK_TIMEOUT = 10.0


class WebhookValidationError(Exception):
    """Raised when a webhook URL fails SSRF validation."""


def _check_ip_allowed(ip_str: str) -> None:
    """Raise WebhookValidationError if the IP is private, loopback, link-local, or reserved."""
    addr = ipaddress.ip_address(ip_str)
    if not addr.is_global or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise WebhookValidationError(
            "Webhook URL must not point to a private or reserved address"
        )


async def _resolve_host(hostname: str, port: int | None) -> list[str]:
    """Resolve a hostname to its IP addresses.

    Isolated in its own function so tests can patch DNS resolution deterministically.
    """
    loop = asyncio.get_event_loop()
    infos = await loop.run_in_executor(
        None, lambda: socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    )
    # Preserve order while dropping duplicates.
    return list(dict.fromkeys(info[4][0] for info in infos))


async def validate_webhook_url(url: str) -> list[str]:
    """Validate a webhook URL against SSRF and return its validated IP addresses.

    Every returned IP has been confirmed global/public. Callers that actually send
    a request should connect to one of these IPs directly (see ``send_webhook``) so
    the hostname cannot be re-resolved to a private address between validation and
    connection (DNS rebinding).

    Raises WebhookValidationError on any problem.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise WebhookValidationError("Invalid webhook URL")

    if parsed.scheme not in ("http", "https"):
        raise WebhookValidationError("Webhook URL must use http or https")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise WebhookValidationError("Webhook URL has no hostname")

    # Block exact matches and subdomains (e.g. foo.localhost, sub.localtest.me).
    if hostname in _BLOCKED_HOSTNAMES or any(
        hostname.endswith("." + h) for h in _BLOCKED_HOSTNAMES
    ):
        raise WebhookValidationError("Webhook URL hostname is not allowed")

    # Bare IP literal — validate directly, no DNS lookup needed.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_bare_ip = False
    else:
        is_bare_ip = True
    if is_bare_ip:
        _check_ip_allowed(hostname)
        return [hostname]

    try:
        ips = await _resolve_host(hostname, parsed.port)
    except socket.gaierror:
        raise WebhookValidationError("Webhook URL hostname could not be resolved")
    if not ips:
        raise WebhookValidationError("Webhook URL hostname could not be resolved")

    for ip_str in ips:
        _check_ip_allowed(ip_str)
    return ips


def _authority(host: str, port: int | None) -> str:
    bracketed = f"[{host}]" if ":" in host else host  # IPv6 literal
    return f"{bracketed}:{port}" if port else bracketed


async def send_webhook(
    client: httpx.AsyncClient,
    url: str,
    payload: dict,
    *,
    timeout: float = _WEBHOOK_TIMEOUT,
) -> httpx.Response:
    """POST a JSON payload to a webhook URL with SSRF protection.

    Re-validates the URL and resolves it to a public IP at send time, then connects
    to that exact IP (pinning) — so the destination cannot be rebound to an internal
    address in the window between validation and the request. The original hostname
    is preserved for the HTTP ``Host`` header and (for https) the TLS SNI / certificate
    verification. Redirects are disabled so a 3xx response cannot bounce the request
    to a private address either.
    """
    validated_ips = await validate_webhook_url(url)
    parsed = urlparse(url)
    host = parsed.hostname  # already lowercased by urlparse

    pinned_ip = validated_ips[0]
    pinned_url = parsed._replace(netloc=_authority(pinned_ip, parsed.port)).geturl()

    headers = {"Host": _authority(host, parsed.port)}
    extensions = {"sni_hostname": host} if parsed.scheme == "https" else {}

    return await client.post(
        pinned_url,
        json=payload,
        headers=headers,
        timeout=timeout,
        follow_redirects=False,
        extensions=extensions,
    )
