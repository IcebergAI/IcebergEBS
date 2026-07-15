"""Structured application logging (#89).

The default format gains a timestamp (``asctime``) so plain ``docker logs`` output is
correlatable with nginx access logs and user reports even when nothing is putting a
timestamp in front of stdout. Set ``ICEBERG_EBS_LOG_JSON=true`` for single-line JSON
records that any log collector can parse without a grok pattern.
"""

import json
import logging

from app.config import settings

_TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Minimal single-line JSON log formatter (stdlib only — no runtime dependency)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    """Configure root logging: timestamped text by default, JSON when ``log_json`` is set.

    Replaces the bare ``logging.basicConfig`` the app used before (which had no
    timestamp). Idempotent — clears existing root handlers so a re-import doesn't
    stack duplicate handlers.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if settings.log_json else logging.Formatter(_TEXT_FORMAT))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.setLevel(logging.INFO)
    root.addHandler(handler)
