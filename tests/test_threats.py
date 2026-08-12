"""Threat-list validation, scoring override, and API acceptance (#31)."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.models import Extension
from app.scoring import compute_risk_score
from app.threat_feed import fetch_threat_feed
from app.threats import finding_for_entries, parse_feed_payload, validate_feed_url


def test_feed_parser_accepts_array_and_deduplicates():
    entries = parse_feed_payload(
        [
            {"store": "Chrome", "extension_id": " abc ", "source": "feed"},
            {"store": "chrome", "extension_id": "abc", "source": "feed", "reason": "same"},
        ],
        default_source="default",
    )
    assert len(entries) == 1
    assert entries[0].store == "chrome"
    assert entries[0].extension_id == "abc"


def test_feed_parser_rejects_malformed_rows():
    with pytest.raises(ValueError, match="every threat feed entry"):
        parse_feed_payload([{"store": "chrome"}], default_source="feed")


def test_feed_url_is_https_without_query_or_credentials():
    assert validate_feed_url("https://feed.example.test/list") == "https://feed.example.test/list"
    for value in (
        "http://feed.example.test/list",
        "https://user:pass@feed.example.test/list",
        "https://feed.example.test/list?token=secret",
    ):
        with pytest.raises(ValueError):
            validate_feed_url(value)


def test_threat_match_forces_critical_without_erasing_signal_breakdown():
    risk = compute_risk_score(
        permissions=[],
        host_permissions=[],
        install_count=100_000,
        install_history=[],
        publisher="Trusted Publisher",
        publisher_changed=False,
        publisher_verified=True,
        last_updated=datetime.now(timezone.utc),
        analysis=None,
        threat_match=True,
    )
    assert risk.total == 100
    assert risk.risk_level == "critical"
    assert risk.permissions == 0
    assert finding_for_entries([])["code"] == "threat_match"


def test_extension_defaults_to_unmatched():
    ext = Extension(
        store="chrome",
        extension_id="abc",
        name="abc",
        publisher="",
        version="",
        store_url="https://example.test",
    )
    assert ext.threat_match is False


async def test_threat_feed_fetch_is_pinned_and_bounded():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://93.184.216.34/list"
        assert request.headers["host"] == "feed.example.test"
        return httpx.Response(200, json={"entries": [{"store": "chrome", "extension_id": "abc"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("app.webhooks._resolve_host", new=AsyncMock(return_value=["93.184.216.34"])):
            entries = await fetch_threat_feed(client, "https://feed.example.test/list", default_source="feed")
    assert entries[0].source == "feed"
