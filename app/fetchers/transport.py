"""Resilient outbound HTTP transport (#108).

The shared ``httpx.AsyncClient`` (built in ``app/main.py``) had a timeout and
nothing else — a single transient blip (a store 502, a reset connection, a DNS
hiccup) permanently failed an extension's refresh until the next scheduled cycle.
``RetryTransport`` wraps the real transport and retries **transient** failures on
**idempotent** requests only, with exponential backoff + full jitter, honouring
``Retry-After`` on 429/503.

Deliberately narrow:
- Only idempotent methods (GET/HEAD/OPTIONS) are retried. POST is never retried —
  webhook delivery goes out as POST and must not be silently re-sent, and its call
  site pins the IP and disables redirects for SSRF safety (``app/webhooks.py``).
- 404 is never retried: for the stores it means the extension was delisted, a
  permanent condition that must surface immediately rather than be hammered.
"""

import asyncio
import email.utils
import logging
import random
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Optional

import httpx

from app import proxy

logger = logging.getLogger(__name__)

# Transient status codes worth retrying an idempotent request on. 404 is
# intentionally absent (delisted extension — permanent, must surface now).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Some store APIs are semantically idempotent reads served over POST (e.g. the VS Code
# gallery `extensionquery`). They opt in to retries per-request via this request
# extension so they get the same resilience as GETs, WITHOUT retrying webhook POSTs
# (which never set it — a re-sent webhook could double-fire an alert).
_RETRY_OPT_IN_EXTENSION = "retry_idempotent"
# Upper bound on a single backoff sleep, including a server-supplied Retry-After.
# The scheduler refreshes extensions sequentially, so an unbounded Retry-After (a
# store replying "retry after 3600") would wedge the whole cycle; a persistently
# unavailable store is handled by the per-store circuit breaker instead.
_MAX_SLEEP_SECONDS = 30.0


def _parse_retry_after(value: str, *, now: datetime | None = None) -> float | None:
    """Parse a ``Retry-After`` value (delta-seconds or HTTP-date) into seconds.

    Returns ``None`` when unparseable. Never returns a negative delay.
    """
    value = value.strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max((dt - now).total_seconds(), 0.0)


def _backoff_delay(attempt: int, *, base: float, cap: float) -> float:
    """Exponential backoff with full jitter: uniform in ``[0, min(cap, base*2**attempt)]``.

    ``attempt`` is 0-based (the first retry passes ``attempt=0``). Full jitter spreads
    a fleet of simultaneous scheduler retries so they don't re-synchronise on a store.
    """
    ceiling = min(cap, base * (2**attempt))
    # Jitter for retry backoff — decorrelating retries, not a security/crypto context.
    return random.uniform(0, max(ceiling, 0.0))  # nosec B311


class ProxyRoutingTransport(httpx.AsyncBaseTransport):
    """Route each request direct or through the configured outbound proxy (#216).

    Consults ``app.proxy.route_for`` per request, so an admin edit at
    /admin/proxy takes effect on the very next outbound request — no client
    rebuild, no cache invalidation. This lives at the transport layer (rather
    than httpx ``mounts=``) because NO_PROXY CIDR entries like ``10.0.0.0/8``
    cannot be expressed as URL patterns, and because a single shared client
    serves every egress path.

    The proxied inner transport is built lazily, keyed on the resolved
    (credential-bearing) proxy URL. When the URL changes, the old transport is
    retired rather than closed — in-flight scheduler/webhook requests finish on
    it — and everything retired is closed in :meth:`aclose` at shutdown. Growth
    is bounded by admin edits per process lifetime. No locking: there is no
    ``await`` between the cache check and the swap, so the section is atomic
    per task on the single event loop (the deployment mandates one worker).

    Deliberately no logging in this class: the resolved proxy URL carries the
    env-only credentials, and a log line here could leak them.
    """

    def __init__(
        self,
        *,
        limits: httpx.Limits,
        transport_factory: Optional[Callable[[Optional[str]], httpx.AsyncBaseTransport]] = None,
    ) -> None:
        self._factory = transport_factory or (
            lambda proxy_url: httpx.AsyncHTTPTransport(limits=limits, proxy=proxy_url)
        )
        self._direct = self._factory(None)
        self._proxied: Optional[tuple[str, httpx.AsyncBaseTransport]] = None
        self._retired: list[httpx.AsyncBaseTransport] = []

    def _transport_for(self, proxy_url: Optional[str]) -> httpx.AsyncBaseTransport:
        if proxy_url is None:
            return self._direct
        if self._proxied is None or self._proxied[0] != proxy_url:
            if self._proxied is not None:
                self._retired.append(self._proxied[1])
            self._proxied = (proxy_url, self._factory(proxy_url))
        return self._proxied[1]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transport_for(proxy.route_for(str(request.url)))
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        await self._direct.aclose()
        if self._proxied is not None:
            await self._proxied[1].aclose()
        for transport in self._retired:
            await transport.aclose()


class RetryTransport(httpx.AsyncBaseTransport):
    """Wrap an inner transport, retrying transient failures on idempotent requests."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        max_retries: int,
        backoff_base: float,
        backoff_cap: float,
    ) -> None:
        self._inner = inner
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap

    async def _sleep(self, attempt: int, retry_after: float | None) -> None:
        delay = (
            retry_after
            if retry_after is not None
            else _backoff_delay(attempt, base=self._backoff_base, cap=self._backoff_cap)
        )
        await asyncio.sleep(min(delay, _MAX_SLEEP_SECONDS))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        retryable_method = request.method in _IDEMPOTENT_METHODS or bool(
            request.extensions.get(_RETRY_OPT_IN_EXTENSION)
        )
        attempt = 0
        while True:
            try:
                response = await self._inner.handle_async_request(request)
            except httpx.TransportError as exc:
                if not retryable_method or attempt >= self._max_retries:
                    raise
                logger.warning(
                    "Retrying %s %s after transport error (%s): attempt %d/%d",
                    request.method,
                    request.url,
                    exc,
                    attempt + 1,
                    self._max_retries,
                )
                await self._sleep(attempt, None)
                attempt += 1
                continue

            if retryable_method and response.status_code in RETRYABLE_STATUS and attempt < self._max_retries:
                # Drain + close the body before retrying or the connection leaks
                # back to the pool half-read.
                await response.aread()
                await response.aclose()
                retry_after: float | None = None
                if response.status_code in (429, 503):
                    header = response.headers.get("retry-after")
                    if header:
                        retry_after = _parse_retry_after(header)
                logger.warning(
                    "Retrying %s %s after HTTP %d: attempt %d/%d",
                    request.method,
                    request.url,
                    response.status_code,
                    attempt + 1,
                    self._max_retries,
                )
                await self._sleep(attempt, retry_after)
                attempt += 1
                continue

            return response

    async def aclose(self) -> None:
        await self._inner.aclose()


if TYPE_CHECKING:
    from app.config import Settings


def build_egress_transport(settings: "Settings") -> RetryTransport:
    """The one egress transport recipe: retry over proxy-routing.

    Shared by the main HTTP client (``app/main.py``) and OIDC egress
    (``app/oidc/service.py``) so a retry/limits/backoff change lands in one place
    instead of two hand-built copies that drift. ``limits`` go on the innermost
    transport because httpx ignores ``AsyncClient(limits=...)`` when a custom
    ``transport=`` is supplied; retry wraps routing so every attempt re-routes (an
    admin fixing a broken proxy takes effect mid-backoff, and proxy connect failures
    are ``TransportError``s that get the normal retry/backoff). Each call builds its
    OWN direct+proxied pools, so N independent chains cap process-wide connections at
    ``N × 2 × httpx_max_connections`` (the main client + the OIDC chain ⇒ 4×).
    """
    limits = httpx.Limits(
        max_connections=settings.httpx_max_connections,
        max_keepalive_connections=settings.httpx_max_keepalive_connections,
    )
    return RetryTransport(
        ProxyRoutingTransport(limits=limits),
        max_retries=settings.httpx_max_retries,
        backoff_base=settings.httpx_backoff_base,
        backoff_cap=settings.httpx_backoff_cap,
    )
