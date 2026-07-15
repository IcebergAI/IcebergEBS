"""Tests for the resilient outbound transport (#108).

RetryTransport retries transient failures on idempotent requests only, with backoff
and Retry-After handling, and never retries 404 or non-idempotent methods (webhook
POSTs must not be silently re-sent).
"""

import httpx
import pytest

from app.fetchers import transport as tmod
from app.fetchers.transport import RetryTransport, _backoff_delay, _parse_retry_after


class _SequenceTransport(httpx.AsyncBaseTransport):
    """Inner transport that yields programmed responses/exceptions in order."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        result = self._results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def no_sleep(monkeypatch):
    """Replace the transport's asyncio.sleep with a recorder so tests don't block."""
    delays: list[float] = []

    async def _record(delay):
        delays.append(delay)

    monkeypatch.setattr(tmod.asyncio, "sleep", _record)
    return delays


def _wrap(inner, *, max_retries=3, base=0.0, cap=0.0):
    return RetryTransport(inner, max_retries=max_retries, backoff_base=base, backoff_cap=cap)


async def test_retries_5xx_then_succeeds(no_sleep):
    inner = _SequenceTransport([httpx.Response(503), httpx.Response(200)])
    resp = await _wrap(inner).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert resp.status_code == 200
    assert inner.calls == 2


async def test_does_not_retry_404(no_sleep):
    inner = _SequenceTransport([httpx.Response(404)])
    resp = await _wrap(inner).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert resp.status_code == 404
    assert inner.calls == 1


async def test_does_not_retry_post_even_on_5xx(no_sleep):
    # Webhook delivery is POST — never retry it (and its call site disables redirects).
    inner = _SequenceTransport([httpx.Response(503)])
    resp = await _wrap(inner).handle_async_request(httpx.Request("POST", "http://hook/x"))
    assert resp.status_code == 503
    assert inner.calls == 1


async def test_retries_opt_in_post(no_sleep):
    # A semantically-idempotent POST (e.g. the VS Code gallery query) opts in and retries.
    inner = _SequenceTransport([httpx.Response(503), httpx.Response(200)])
    req = httpx.Request("POST", "http://store/x", extensions={"retry_idempotent": True})
    resp = await _wrap(inner).handle_async_request(req)
    assert resp.status_code == 200
    assert inner.calls == 2


async def test_gives_up_after_max_retries(no_sleep):
    inner = _SequenceTransport([httpx.Response(503)] * 4)
    resp = await _wrap(inner, max_retries=3).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert resp.status_code == 503
    assert inner.calls == 4  # 1 initial + 3 retries


async def test_retries_transport_error_then_succeeds(no_sleep):
    inner = _SequenceTransport([httpx.ConnectError("boom"), httpx.Response(200)])
    resp = await _wrap(inner).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert resp.status_code == 200
    assert inner.calls == 2


async def test_transport_error_exhausts_and_raises(no_sleep):
    inner = _SequenceTransport([httpx.ConnectError("boom")] * 5)
    with pytest.raises(httpx.ConnectError):
        await _wrap(inner, max_retries=2).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert inner.calls == 3  # 1 initial + 2 retries, then re-raised


async def test_honours_retry_after_header(no_sleep):
    inner = _SequenceTransport([httpx.Response(503, headers={"Retry-After": "7"}), httpx.Response(200)])
    resp = await _wrap(inner, base=0.0, cap=0.0).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert resp.status_code == 200
    # Retry-After (7s) was honoured for the backoff, not the zero jittered default.
    assert no_sleep == [7.0]


async def test_retry_after_is_capped(no_sleep):
    # A hostile/huge Retry-After must not wedge the sequential scheduler.
    inner = _SequenceTransport([httpx.Response(503, headers={"Retry-After": "99999"}), httpx.Response(200)])
    await _wrap(inner).handle_async_request(httpx.Request("GET", "http://store/x"))
    assert no_sleep == [tmod._MAX_SLEEP_SECONDS]


def test_parse_retry_after_seconds():
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after("  12 ") == 12.0


def test_parse_retry_after_unparseable():
    assert _parse_retry_after("") is None
    assert _parse_retry_after("soon") is None


def test_parse_retry_after_http_date_never_negative():
    # A date in the past yields 0, never a negative delay.
    assert _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


def test_backoff_delay_within_ceiling():
    for attempt in range(5):
        d = _backoff_delay(attempt, base=0.5, cap=10.0)
        assert 0.0 <= d <= min(10.0, 0.5 * (2**attempt))
