"""Application-level login throttling (M3 / #8).

Defense-in-depth that does not depend on a reverse proxy: counts failed login
attempts per (client IP + username) and locks the pair out for a cooldown once a
threshold is reached within a rolling window. State is in-process, which is
sufficient because the deployment mandates a single uvicorn worker (see
DEPLOYMENT.md / CLAUDE.md).
"""

import time
from dataclasses import dataclass, field

from app.config import settings

# Cap on distinct tracked keys, so a spray of unique usernames/IPs can't grow the
# map without bound. When exceeded we drop expired entries first, then the oldest.
_MAX_ENTRIES = 10_000


@dataclass
class _Entry:
    failures: int = 0
    window_start: float = field(default_factory=time.monotonic)
    locked_until: float = 0.0


class LoginRateLimiter:
    def __init__(
        self,
        max_attempts: int,
        window_seconds: float,
        lockout_seconds: float,
        *,
        now=time.monotonic,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._now = now
        self._entries: dict[str, _Entry] = {}

    @staticmethod
    def key(ip: str | None, username: str) -> str:
        return f"{ip or '-'}|{username.lower()}"

    def retry_after(self, key: str) -> int | None:
        """Seconds remaining on an active lockout for ``key``, or None if allowed."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        remaining = entry.locked_until - self._now()
        return int(remaining) + 1 if remaining > 0 else None

    def record_failure(self, key: str) -> None:
        now = self._now()
        entry = self._entries.get(key)
        # Start a fresh window if there is none or the previous one has elapsed.
        if entry is None or (now - entry.window_start) > self.window_seconds:
            entry = _Entry(failures=0, window_start=now)
            self._entries[key] = entry
        entry.failures += 1
        if entry.failures >= self.max_attempts:
            entry.locked_until = now + self.lockout_seconds
        self._maybe_prune()

    def reset(self, key: str) -> None:
        self._entries.pop(key, None)

    def _maybe_prune(self) -> None:
        if len(self._entries) <= _MAX_ENTRIES:
            return
        now = self._now()
        # Drop entries whose window and lockout have both expired.
        for k in [
            k
            for k, e in self._entries.items()
            if e.locked_until <= now and (now - e.window_start) > self.window_seconds
        ]:
            del self._entries[k]
        # If still over budget, evict oldest by window_start.
        if len(self._entries) > _MAX_ENTRIES:
            for k, _ in sorted(self._entries.items(), key=lambda kv: kv[1].window_start)[
                : len(self._entries) - _MAX_ENTRIES
            ]:
                del self._entries[k]


# Process-wide singleton used by the login route.
login_limiter = LoginRateLimiter(
    max_attempts=settings.login_max_attempts,
    window_seconds=settings.login_attempt_window_seconds,
    lockout_seconds=settings.login_lockout_seconds,
)


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RequestRateLimiter:
    """Token-bucket request-rate limiter keyed on client IP (#188).

    The app-side equivalent of the old nginx ``api`` ``limit_req`` zone, added when the
    reverse proxy became Caddy (stock Caddy has no rate_limit directive). ``per_minute``
    is the sustained refill rate; ``burst`` is the bucket capacity (the number of
    requests allowed to arrive back-to-back before throttling kicks in). Each allowed
    request consumes one token; when the bucket is empty the caller is told how many
    seconds until the next token. In-process state, like ``LoginRateLimiter`` — fine
    because the deployment mandates a single worker.
    """

    def __init__(self, per_minute: int, burst: int, *, now=time.monotonic) -> None:
        self.rate_per_second = per_minute / 60.0
        self.burst = float(burst)
        self._now = now
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str) -> int | None:
        """Consume a token for ``key``. Return None if allowed, else the integer
        ``Retry-After`` seconds until the next token is available."""
        now = self._now()
        bucket = self._buckets.get(key)
        if bucket is None:
            # A new client starts with a full bucket.
            bucket = _Bucket(tokens=self.burst, updated=now)
            self._buckets[key] = bucket
        else:
            # Refill proportional to elapsed time, capped at the burst size.
            elapsed = now - bucket.updated
            bucket.updated = now
            bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate_per_second)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            self._maybe_prune()
            return None
        # Empty: seconds until the bucket accrues one whole token (rate_per_second > 0).
        return int((1.0 - bucket.tokens) / self.rate_per_second) + 1

    def _maybe_prune(self) -> None:
        if len(self._buckets) <= _MAX_ENTRIES:
            return
        now = self._now()
        # Drop buckets that have fully refilled (idle long enough to be back at capacity):
        # they carry no state a fresh bucket wouldn't reproduce.
        for k in [
            k for k, b in self._buckets.items() if b.tokens + (now - b.updated) * self.rate_per_second >= self.burst
        ]:
            del self._buckets[k]
        # If still over budget, evict least-recently-updated.
        if len(self._buckets) > _MAX_ENTRIES:
            for k, _ in sorted(self._buckets.items(), key=lambda kv: kv[1].updated)[
                : len(self._buckets) - _MAX_ENTRIES
            ]:
                del self._buckets[k]


# Process-wide singletons used by the edge rate-limit middleware (app/main.py):
# one bucket for the JSON API, a separate (tighter) one for POST /login (#196).
api_limiter = RequestRateLimiter(
    per_minute=settings.api_rate_limit_per_minute,
    burst=settings.api_rate_limit_burst,
)
login_request_limiter = RequestRateLimiter(
    per_minute=settings.login_rate_limit_per_minute,
    burst=settings.login_rate_limit_burst,
)
