"""Observability baseline (#89): structured logs, scheduler visibility, nginx log fields."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.logging_config import _TEXT_FORMAT, JsonFormatter, setup_logging
from app.models import Extension, FetchLog

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


async def test_readyz_reports_last_successful_refresh_null(anon_client):
    body = (await anon_client.get("/readyz")).json()
    # Key is always present; null when the scheduler hasn't logged a successful refresh.
    assert "last_successful_refresh" in body
    assert body["last_successful_refresh"] is None


async def test_readyz_reports_last_successful_refresh(anon_client, test_db, admin_user):
    now = datetime.now(timezone.utc)
    async with AsyncSession(test_db) as s:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="e" * 32,
            name="E",
            publisher="p",
            version="1.0",
            store_url="https://example.com",
            risk_score=10,
        )
        s.add(ext)
        await s.commit()
        await s.refresh(ext)
        s.add(FetchLog(extension_id=ext.id, success=True, fetched_at=now))
        s.add(FetchLog(extension_id=ext.id, success=False, fetched_at=now, error_message="ignored"))
        await s.commit()

    body = (await anon_client.get("/readyz")).json()
    assert body["last_successful_refresh"] is not None
    # It reflects the successful row, not the later failed one.
    assert body["last_successful_refresh"].startswith(now.isoformat()[:19])


def test_nginx_log_format_has_ua_and_timing():
    conf = _NGINX_CONF.read_text()
    assert "$http_user_agent" in conf
    assert "$http_referer" in conf
    assert "$upstream_response_time" in conf
