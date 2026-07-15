"""In-process scheduler health signal (#89).

Records when the background scheduler last completed a watchlist refresh cycle, read by
``/readyz`` so an external monitor can catch a stalled scheduler WITHOUT scanning the
(unbounded) history table on every probe. In-memory on purpose:

- it reflects only the **scheduler**, so an API-triggered fetch can't mask a stalled one;
- a fresh process reports ``null`` until its first cycle (correct — nothing has run yet);
- it is safe as a module global because the deployment mandates a single worker and the
  scheduler shares this process.
"""

from datetime import datetime, timezone

_last_run: datetime | None = None


def mark_scheduler_run() -> None:
    """Record that the scheduler just completed a refresh cycle."""
    global _last_run
    _last_run = datetime.now(timezone.utc)


def last_scheduler_run() -> datetime | None:
    return _last_run
