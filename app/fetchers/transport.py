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

import httpx

logger = logging.getLogger(__name__)

# Transient status codes worth retrying an idempotent request on. 404 is
# intentionally absent (delisted extension — permanent, must surface now).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
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
    return random.uniform(0, max(ceiling, 0.0))


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
        retryable_method = request.method in _IDEMPOTENT_METHODS
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
