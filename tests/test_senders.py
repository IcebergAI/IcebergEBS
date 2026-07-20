"""Sender-adapter tests (#37): registry, per-kind validation + payload shapes."""

import base64
import re
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.config import settings
from app.models import AlertDestination
from app.senders import (
    AlertMessage,
    DestinationConfigError,
    all_senders,
    get_sender,
    kind_descriptors,
    sender_kinds,
)
from app.senders.email import EmailSender, _is_valid_address
from app.senders.tickets import _SECRET_ENV_PREFIX

_EXPECTED_KINDS = ("webhook", "slack", "teams", "email", "jira", "servicenow")

# A fixed public IP the SSRF resolver is patched to, so the pinned-send path is
# exercised deterministically (mirrors tests/test_alerts.py).
_PINNED_IP = "93.184.216.34"


def _patch_resolver(ip: str = _PINNED_IP):
    return patch("app.webhooks._resolve_host", new=AsyncMock(return_value=[ip]))


def _msg(**kw) -> AlertMessage:
    defaults = dict(
        text="IcebergEBS: Ext risk level changed low → high",
        event="risk_level_change",
        ext_id=7,
        name="Ext",
        store="chrome",
        store_url="https://store/ext",
        old="low",
        new="high",
        risk_score=62,
        app_url="https://ebs.example.com/extensions/7",
    )
    defaults.update(kw)
    return AlertMessage(**defaults)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_has_all_kinds():
    assert sender_kinds() == _EXPECTED_KINDS
    assert [s.kind for s in all_senders()] == list(_EXPECTED_KINDS)
    for kind in _EXPECTED_KINDS:
        assert get_sender(kind) is not None
    assert get_sender("nope") is None


def test_kind_descriptors_shape():
    descriptors = {d["kind"]: d for d in kind_descriptors()}
    assert set(descriptors) == set(_EXPECTED_KINDS)
    for d in descriptors.values():
        assert d["label"] and d["target_label"]
        assert isinstance(d["config_fields"], list)
        assert isinstance(d["available"], bool)
    # Jira exposes its config inputs to the dynamic form.
    jira_fields = {f["name"] for f in descriptors["jira"]["config_fields"]}
    assert {"project_key", "issue_type", "account_email", "secret_ref"} <= jira_fields


def test_model_check_constraint_matches_registry():
    """The DB CHECK on AlertDestination.kind must list exactly the registered kinds —
    the schema backstop and the app registry can't be allowed to drift (#37)."""
    check = next(c for c in AlertDestination.__table__.constraints if c.name == "ck_alertdestination_kind")
    kinds_in_check = set(re.findall(r"'([a-z]+)'", str(check.sqltext)))
    assert kinds_in_check == set(sender_kinds())


# ---------------------------------------------------------------------------
# Payload shapes (rendered without network)
# ---------------------------------------------------------------------------


def test_webhook_payload_is_canonical_shape():
    payload = get_sender("webhook").render_payload(_msg(), {})
    assert payload["event"] == "risk_level_change"
    assert payload["change"] == {"old": "low", "new": "high"}
    assert payload["extension"]["id"] == 7
    assert payload["risk_score"] == 62


def test_slack_payload_has_text_and_blocks():
    payload = get_sender("slack").render_payload(_msg(), {})
    assert payload["text"].startswith("IcebergEBS:")
    section = payload["blocks"][0]
    assert section["type"] == "section"
    assert "risk_level change" in section["text"]["text"] or "*Change:*" in section["text"]["text"]
    # The deep-link button is present when app_url is set.
    assert any(b["type"] == "actions" for b in payload["blocks"])


def test_slack_payload_without_app_url_has_no_button():
    payload = get_sender("slack").render_payload(_msg(app_url=None), {})
    assert all(b["type"] != "actions" for b in payload["blocks"])


def test_teams_payload_is_adaptive_card_envelope():
    payload = get_sender("teams").render_payload(_msg(), {})
    assert payload["type"] == "message"
    attachment = payload["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    assert any(block.get("type") == "FactSet" for block in card["body"])
    assert card["actions"][0]["type"] == "Action.OpenUrl"


def test_jira_payload_is_adf_issue():
    payload = get_sender("jira").render_payload(_msg(), {"project_key": "SEC", "issue_type": "Bug"})
    assert payload["fields"]["project"]["key"] == "SEC"
    assert payload["fields"]["issuetype"]["name"] == "Bug"
    assert payload["fields"]["summary"].startswith("IcebergEBS:")
    assert payload["fields"]["description"]["type"] == "doc"


def test_jira_issue_type_defaults_to_task():
    payload = get_sender("jira").render_payload(_msg(), {"project_key": "SEC"})
    assert payload["fields"]["issuetype"]["name"] == "Task"


def test_servicenow_payload_uses_short_description():
    payload = get_sender("servicenow").render_payload(_msg(), {})
    assert payload["short_description"].startswith("IcebergEBS:")
    assert "Risk score: 62" in payload["description"]


def test_servicenow_endpoint_url_uses_table():
    sender = get_sender("servicenow")
    assert sender.endpoint_url("https://dev.service-now.com/", {}) == (
        "https://dev.service-now.com/api/now/table/incident"
    )
    assert sender.endpoint_url("https://dev.service-now.com", {"table": "sn_si_incident"}) == (
        "https://dev.service-now.com/api/now/table/sn_si_incident"
    )


def test_jira_endpoint_url_appends_api_path():
    assert get_sender("jira").endpoint_url("https://x.atlassian.net/", {}) == (
        "https://x.atlassian.net/rest/api/3/issue"
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


async def test_webhook_validate_rejects_private_target():
    with patch("app.webhooks._resolve_host", new=AsyncMock(return_value=["10.0.0.5"])):
        with pytest.raises(DestinationConfigError):
            await get_sender("webhook").validate("https://rebind.example.com/hook", {})


async def test_jira_validate_requires_fields_and_secret(monkeypatch):
    sender = get_sender("jira")
    with _patch_resolver():
        # Missing project key.
        with pytest.raises(DestinationConfigError, match="project key"):
            await sender.validate("https://x.atlassian.net", {"account_email": "a@b.com", "secret_ref": "JIRA_TOKEN"})
        # Missing/unset secret ref.
        with pytest.raises(DestinationConfigError, match="environment variable"):
            await sender.validate(
                "https://x.atlassian.net",
                {"project_key": "SEC", "account_email": "a@b.com", "secret_ref": "JIRA_TOKEN"},
            )
        # Valid once the env var is present.
        monkeypatch.setenv(_SECRET_ENV_PREFIX + "JIRA_TOKEN", "tok")
        await sender.validate(
            "https://x.atlassian.net",
            {"project_key": "SEC", "account_email": "a@b.com", "secret_ref": "JIRA_TOKEN"},
        )


async def test_secret_ref_must_be_upper_snake(monkeypatch):
    sender = get_sender("servicenow")
    with _patch_resolver():
        with pytest.raises(DestinationConfigError, match="UPPER_SNAKE_CASE"):
            await sender.validate("https://dev.service-now.com", {"username": "svc", "secret_ref": "lower-case"})


# ---------------------------------------------------------------------------
# Ticketing auth header + delivery (respx)
# ---------------------------------------------------------------------------


@respx.mock
async def test_jira_send_posts_with_basic_auth(monkeypatch):
    monkeypatch.setenv(_SECRET_ENV_PREFIX + "JIRA_TOKEN", "s3cret")
    route = respx.post(f"https://{_PINNED_IP}/rest/api/3/issue").mock(return_value=httpx.Response(201))
    config = {"project_key": "SEC", "account_email": "bot@example.com", "secret_ref": "JIRA_TOKEN"}
    with _patch_resolver():
        async with httpx.AsyncClient() as http:
            await get_sender("jira").send(http, "https://jira.example.com", config, _msg())
    assert route.called
    req = route.calls[0].request
    assert req.headers["Host"] == "jira.example.com"  # SSRF pinning preserves Host
    expected = "Basic " + base64.b64encode(b"bot@example.com:s3cret").decode()
    assert req.headers["Authorization"] == expected


@respx.mock
async def test_jira_send_raises_when_secret_removed():
    """secret_ref validated at create, but if the env var is gone at send time the
    sender raises a caller-safe SenderError rather than sending an unauthenticated call."""
    config = {"project_key": "SEC", "account_email": "bot@example.com", "secret_ref": "GONE_TOKEN"}
    with _patch_resolver():
        async with httpx.AsyncClient() as http:
            with pytest.raises(Exception) as exc_info:
                await get_sender("jira").send(http, "https://jira.example.com", config, _msg())
    assert "GONE_TOKEN" in str(exc_info.value)
    assert respx.calls.call_count == 0


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


def test_email_address_validation():
    assert _is_valid_address("a@b.com")
    assert _is_valid_address("Ops <ops@example.com>")
    assert not _is_valid_address("not-an-email")
    assert not _is_valid_address("@example.com")
    assert not _is_valid_address("a@localhost")  # no dot in domain


async def test_email_unavailable_without_smtp(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "")
    available, reason = EmailSender().availability()
    assert not available and "SMTP" in reason
    with pytest.raises(DestinationConfigError, match="unavailable"):
        await EmailSender().validate("a@b.com", {})


async def test_email_validate_rejects_bad_recipient(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from", "ebs@example.com")
    with pytest.raises(DestinationConfigError, match="Invalid recipient"):
        await EmailSender().validate("good@example.com, bad-addr", {})


async def test_email_send_delivers_via_smtp(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from", "ebs@example.com")
    monkeypatch.setattr(settings, "smtp_username", "")

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["starttls"] = True

        def login(self, user, password):
            sent["login"] = (user, password)

        def send_message(self, msg):
            sent["to"] = msg["To"]
            sent["subject"] = msg["Subject"]
            sent["body"] = msg.get_content()

    monkeypatch.setattr("app.senders.email.smtplib.SMTP", FakeSMTP)
    await EmailSender().send(MagicMock(), "ops@example.com, sec@example.com", {"subject_prefix": "[EBS]"}, _msg())
    assert sent["host"] == "smtp.example.com"
    assert sent["to"] == "ops@example.com, sec@example.com"
    assert sent["subject"].startswith("[EBS] IcebergEBS:")
    assert "Risk score: 62" in sent["body"]
    assert "login" not in sent  # no smtp_username → no login attempted
