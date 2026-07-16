"""App-side API request-rate limiting (#188).

The token-bucket limiter and its middleware replaced the nginx `api` limit_req zone
when the edge proxy became Caddy (which has no built-in rate_limit).
"""

from app.ratelimit import RequestRateLimiter


def test_request_limiter_allows_burst_then_throttles():
    t = [1000.0]
    rl = RequestRateLimiter(per_minute=60, burst=3, now=lambda: t[0])
    # A fresh key starts with a full bucket: burst requests pass back-to-back.
    assert rl.check("1.2.3.4") is None
    assert rl.check("1.2.3.4") is None
    assert rl.check("1.2.3.4") is None
    # Bucket empty → throttled, with a positive Retry-After.
    retry = rl.check("1.2.3.4")
    assert retry is not None and retry >= 1


def test_request_limiter_refills_over_time():
    t = [0.0]
    rl = RequestRateLimiter(per_minute=60, burst=1, now=lambda: t[0])  # 1 token/sec
    assert rl.check("ip") is None  # consume the only token
    assert rl.check("ip") is not None  # empty → throttled
    t[0] += 1.0  # one second elapses → one token refilled
    assert rl.check("ip") is None  # allowed again


def test_request_limiter_partial_refill_still_throttles():
    t = [0.0]
    rl = RequestRateLimiter(per_minute=60, burst=1, now=lambda: t[0])  # 1 token/sec
    assert rl.check("ip") is None
    t[0] += 0.5  # only half a token back
    assert rl.check("ip") is not None  # still below 1 → throttled


def test_request_limiter_keys_are_independent():
    t = [0.0]
    rl = RequestRateLimiter(per_minute=60, burst=1, now=lambda: t[0])
    assert rl.check("a") is None
    assert rl.check("b") is None  # distinct client, its own bucket
    assert rl.check("a") is not None  # "a" is exhausted, "b" was unaffected


async def test_api_rate_limit_middleware_returns_429(client, monkeypatch):
    """With the limiter enabled and a tiny burst, the API 429s once the bucket drains,
    and includes a Retry-After header. Disabled by default so normal tests aren't hit."""
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "api_rate_limit_enabled", True)
    # per_minute low enough that three back-to-back requests don't meaningfully refill.
    monkeypatch.setattr(main_module, "api_limiter", RequestRateLimiter(per_minute=60, burst=2))

    assert (await client.get("/api/extensions")).status_code == 200
    assert (await client.get("/api/extensions")).status_code == 200
    throttled = await client.get("/api/extensions")
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers


async def test_api_rate_limit_off_by_default(client):
    """The limiter is disabled unless api_rate_limit_enabled is set, so a burst of API
    calls in a normal test never 429s."""
    for _ in range(30):
        assert (await client.get("/api/extensions")).status_code == 200


async def test_non_api_paths_are_not_rate_limited(client, monkeypatch):
    """Only /api/* is throttled — the dashboard/UI is never rate-limited app-side."""
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "api_rate_limit_enabled", True)
    monkeypatch.setattr(main_module, "api_limiter", RequestRateLimiter(per_minute=60, burst=1))
    for _ in range(5):
        assert (await client.get("/")).status_code == 200
