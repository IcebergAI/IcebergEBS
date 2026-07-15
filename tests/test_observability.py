"""Observability baseline (#89): structured logs, scheduler visibility, nginx log fields."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app import scheduler_state
from app.config import settings
from app.logging_config import _TEXT_FORMAT, JsonFormatter, setup_logging

_NGINX_CONF = Path(__file__).resolve().parent.parent / "nginx" / "nginx.conf"


def test_text_format_includes_timestamp():
    # The old bare format had no timestamp; docker logs must now be self-timestamping.
    assert "asctime" in _TEXT_FORMAT


def test_json_formatter_emits_valid_single_line_json():
    rec = logging.LogRecord("app.test", logging.INFO, __file__, 10, "hello %s", ("world",), None)
    out = JsonFormatter().format(rec)
    assert "\n" not in out
    parsed = json.loads(out)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "app.test"
    assert parsed["msg"] == "hello world"
    assert "ts" in parsed


def test_json_formatter_includes_exception():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        rec = logging.LogRecord("app.test", logging.ERROR, __file__, 10, "failed", (), sys.exc_info())
    parsed = json.loads(JsonFormatter().format(rec))
    assert "boom" in parsed["exc"]


def test_setup_logging_selects_formatter(monkeypatch):
    monkeypatch.setattr(settings, "log_json", True)
    setup_logging()
    assert isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)
    monkeypatch.setattr(settings, "log_json", False)
    setup_logging()
    assert not isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)


async def test_readyz_reports_last_scheduler_run_null(anon_client, monkeypatch):
    monkeypatch.setattr(scheduler_state, "_last_run", None)
    body = (await anon_client.get("/readyz")).json()
    # Key is always present; null until the scheduler has completed a cycle this process.
    assert "last_scheduler_run" in body
    assert body["last_scheduler_run"] is None


async def test_readyz_reports_last_scheduler_run(anon_client, monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(scheduler_state, "_last_run", now)
    body = (await anon_client.get("/readyz")).json()
    assert body["last_scheduler_run"] is not None
    assert body["last_scheduler_run"].startswith(now.isoformat()[:19])


def test_mark_scheduler_run_records_timestamp(monkeypatch):
    monkeypatch.setattr(scheduler_state, "_last_run", None)
    scheduler_state.mark_scheduler_run()
    assert scheduler_state.last_scheduler_run() is not None


def test_setup_logging_routes_uvicorn_loggers_through_root():
    # Uvicorn's own loggers must lose their handlers + propagate, so LOG_JSON applies to
    # uvicorn/access lines too instead of leaving them in the default text format.
    setup_logging()
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        assert lg.handlers == []
        assert lg.propagate is True


def test_nginx_log_format_has_ua_and_timing():
    conf = _NGINX_CONF.read_text()
    assert "$http_user_agent" in conf
    assert "$http_referer" in conf
    assert "$upstream_response_time" in conf
