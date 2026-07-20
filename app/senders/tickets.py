"""Ticketing senders — Jira Cloud + ServiceNow (#37).

Both are ``HttpJsonSender`` kinds that add an ``Authorization`` header and append a
create-issue API path to the stored base URL. They are create-only (no status
readback / dedup), matching the issue's scope.

Secrets are env-only, mirroring the OIDC client secrets and proxy credentials: the
destination row stores a **``secret_ref``** — an uppercase name, *not* a secret —
and the API token / password is read at send time from the environment variable
``ICEBERG_EBS_DEST_SECRET_<REF>``. The ref is safe to return from the API and show
in the UI; the credential never touches the DB. ``validate`` checks the ref resolves
at create/update time (fail fast); ``send`` re-reads it per delivery, so a rotated
env value applies on restart without editing the row.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any, Mapping

from app.senders.base import AlertMessage, ConfigField, DestinationConfigError, SenderError, register_sender
from app.senders.content import detail_text
from app.senders.http import HttpJsonSender

_SECRET_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Not a secret: the env-var *name* prefix a destination's secret_ref is appended to.
_SECRET_ENV_PREFIX = "ICEBERG_EBS_DEST_SECRET_"  # nosec B105 — env var name prefix, not a password


def _validate_secret_ref(config: Mapping[str, str]) -> str:
    ref = (config.get("secret_ref") or "").strip()
    if not ref:
        raise DestinationConfigError("A secret reference is required")
    if not _SECRET_REF_RE.match(ref):
        raise DestinationConfigError(
            "Secret reference must be an UPPER_SNAKE_CASE name (it points at an "
            f"{_SECRET_ENV_PREFIX}<REF> environment variable, not the secret itself)"
        )
    if os.environ.get(_SECRET_ENV_PREFIX + ref) is None:
        raise DestinationConfigError(f"No {_SECRET_ENV_PREFIX}{ref} environment variable is set")
    return ref


def _resolve_secret(ref: str) -> str:
    value = os.environ.get(_SECRET_ENV_PREFIX + ref)
    if value is None:
        # Validated at create/update time; a None here means the env var was
        # removed since. Raise a caller-safe SenderError (the ref name is not secret).
        raise SenderError(f"Missing {_SECRET_ENV_PREFIX}{ref} environment variable")
    return value


def _basic_auth(username: str, secret: str) -> str:
    token = base64.b64encode(f"{username}:{secret}".encode()).decode()
    return f"Basic {token}"


def _adf_description(text: str) -> dict[str, Any]:
    """Atlassian Document Format doc: one paragraph per line."""
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in text.split("\n")],
    }


class JiraSender(HttpJsonSender):
    kind = "jira"
    label = "Jira"
    target_label = "Jira site base URL"
    config_fields: tuple[ConfigField, ...] = (
        ConfigField("project_key", "Project key", placeholder="SEC"),
        ConfigField("issue_type", "Issue type", required=False, placeholder="Task"),
        ConfigField("account_email", "Account email", placeholder="bot@example.com"),
        ConfigField(
            "secret_ref",
            "API-token secret ref",
            placeholder="JIRA_TOKEN",
            help="Name of the ICEBERG_EBS_DEST_SECRET_<REF> env var holding the Jira API token.",
        ),
    )

    def endpoint_url(self, target: str, config: Mapping[str, str]) -> str:
        return target.rstrip("/") + "/rest/api/3/issue"

    def validate_config(self, config: Mapping[str, str]) -> None:
        if not (config.get("project_key") or "").strip():
            raise DestinationConfigError("A Jira project key is required")
        if not (config.get("account_email") or "").strip():
            raise DestinationConfigError("A Jira account email is required")
        _validate_secret_ref(config)

    def request_headers(self, config: Mapping[str, str]) -> dict[str, str]:
        secret = _resolve_secret((config.get("secret_ref") or "").strip())
        return {"Authorization": _basic_auth((config.get("account_email") or "").strip(), secret)}

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        issue_type = (config.get("issue_type") or "").strip() or "Task"
        return {
            "fields": {
                "project": {"key": (config.get("project_key") or "").strip()},
                "issuetype": {"name": issue_type},
                "summary": message.text,
                "description": _adf_description(detail_text(message)),
            }
        }


class ServiceNowSender(HttpJsonSender):
    kind = "servicenow"
    label = "ServiceNow"
    target_label = "ServiceNow instance base URL"
    config_fields: tuple[ConfigField, ...] = (
        ConfigField("table", "Table", required=False, placeholder="incident"),
        ConfigField("username", "Username", placeholder="svc_iceberg"),
        ConfigField(
            "secret_ref",
            "Password secret ref",
            placeholder="SERVICENOW_PW",
            help="Name of the ICEBERG_EBS_DEST_SECRET_<REF> env var holding the ServiceNow password.",
        ),
    )

    def _table(self, config: Mapping[str, str]) -> str:
        return (config.get("table") or "").strip() or "incident"

    def endpoint_url(self, target: str, config: Mapping[str, str]) -> str:
        return f"{target.rstrip('/')}/api/now/table/{self._table(config)}"

    def validate_config(self, config: Mapping[str, str]) -> None:
        if not (config.get("username") or "").strip():
            raise DestinationConfigError("A ServiceNow username is required")
        table = self._table(config)
        if not re.match(r"^[a-z0-9_]+$", table):
            raise DestinationConfigError("ServiceNow table must be a lower_snake_case name")
        _validate_secret_ref(config)

    def request_headers(self, config: Mapping[str, str]) -> dict[str, str]:
        secret = _resolve_secret((config.get("secret_ref") or "").strip())
        return {"Authorization": _basic_auth((config.get("username") or "").strip(), secret)}

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        return {"short_description": message.text, "description": detail_text(message)}


register_sender(JiraSender())
register_sender(ServiceNowSender())
