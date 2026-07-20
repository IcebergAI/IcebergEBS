"""Provider-adapter contract + registry for outbound alert delivery (#37).

A *sender* turns a normalised ``AlertMessage`` into a delivered notification for
one destination kind (generic webhook, Slack, Teams, email, Jira, ServiceNow).
This mirrors the OIDC adapter design (``app/oidc/base.py``): a small, pure
contract module holding the Protocol, the shared value types and the
self-registering registry, with one thin module per kind.

Webhook is **not** privileged here — it is one registered kind among the others.
Structurally Slack and Teams are *specialised webhooks* (the same POST-a-JSON-body
delivery, a different payload shape), so they share the ``HttpJsonSender`` core in
``app/senders/http.py`` the way Authentik/Auth0/Okta share ``StandardOIDCAdapter``.

This module is pure (no network / DB / ORM) and stays in the mypy-enforced set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True)
class AlertMessage:
    """Normalised alert content every sender renders from.

    Assembled once per (event, extension) by ``notifications.fire_alerts`` and by
    the destination-test endpoint, so a "test" delivery is the real delivery path
    by construction (the #168 property, generalised to every kind).
    """

    text: str
    event: str  # event_type, or "test" for a destination test
    ext_id: int | None
    name: str
    store: str
    store_url: str
    old: Any
    new: Any
    risk_score: int | None
    app_url: str | None = None  # IcebergEBS deep link, when app_base_url is configured


@dataclass(frozen=True)
class ConfigField:
    """One kind-specific configuration input, declared by a sender to drive the
    dynamic destination form (the UI renders these; adding a kind is adapter-only).

    ``secret`` marks a field whose *value* is an env-var reference name, never a
    secret itself — see the ``secret_ref`` convention in ``app/senders/tickets.py``.
    """

    name: str
    label: str
    required: bool = True
    placeholder: str = ""
    help: str = ""


class SenderError(Exception):
    """Delivery failure with a caller-safe message (no secrets, no resolved IPs).

    Raised by a sender's ``send`` for a non-transport failure it wants to surface
    with controlled text. Transport exceptions (httpx) may also propagate; both are
    scrubbed + truncated by ``fire_alerts`` before they reach an AlertLog row.
    """


class DestinationConfigError(Exception):
    """Invalid destination target/config, raised by ``validate``.

    Its message is static + user-facing (the same contract as
    ``WebhookValidationError``): the API surfaces it verbatim as a 422 detail.
    """


@runtime_checkable
class AlertSender(Protocol):
    """Per-kind delivery adapter. Stateless; keyed by ``kind``."""

    kind: str  # "webhook" | "slack" | "teams" | "email" | "jira" | "servicenow"
    label: str  # UI display name
    target_label: str  # what ``target`` means for this kind
    config_fields: tuple[ConfigField, ...]  # drives the dynamic config form

    def availability(self) -> tuple[bool, str | None]:
        """(available, reason). ``False`` refuses creation of this kind (e.g. email
        when SMTP is unconfigured); ``reason`` is a static user-facing message."""
        ...

    async def validate(self, target: str, config: Mapping[str, str]) -> None:
        """Validate the destination at create/update time. Raises
        ``DestinationConfigError`` (→ 422) with a static message on any problem."""
        ...

    async def send(
        self,
        client: httpx.AsyncClient,
        target: str,
        config: Mapping[str, str],
        message: AlertMessage,
    ) -> None:
        """Deliver ``message`` to ``target``. Raises on failure (transport error or
        ``SenderError``); the caller records the outcome in an AlertLog row."""
        ...


_REGISTRY: dict[str, AlertSender] = {}

# Canonical display order for the API/UI, independent of module import order (so the
# self-registering imports can be sorted however the linter likes). Unknown kinds
# sort last, alphabetically.
_KIND_ORDER = ("webhook", "slack", "teams", "email", "jira", "servicenow")


def _order_key(kind: str) -> tuple[int, str]:
    return (_KIND_ORDER.index(kind) if kind in _KIND_ORDER else len(_KIND_ORDER), kind)


def register_sender(sender: AlertSender) -> None:
    _REGISTRY[sender.kind] = sender


def get_sender(kind: str) -> AlertSender | None:
    return _REGISTRY.get(kind)


def all_senders() -> list[AlertSender]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY, key=_order_key)]


def sender_kinds() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY, key=_order_key))


def kind_descriptors() -> list[dict[str, Any]]:
    """Serialisable descriptors for every registered kind — consumed by both the
    ``GET /api/alerts/destination-kinds`` endpoint and the account-page JSON island,
    so the dynamic form and API/SOAR consumers discover kinds from one source."""
    out: list[dict[str, Any]] = []
    for sender in all_senders():
        available, reason = sender.availability()
        out.append(
            {
                "kind": sender.kind,
                "label": sender.label,
                "target_label": sender.target_label,
                "config_fields": [
                    {
                        "name": f.name,
                        "label": f.label,
                        "required": f.required,
                        "placeholder": f.placeholder,
                        "help": f.help,
                    }
                    for f in sender.config_fields
                ],
                "available": available,
                "unavailable_reason": reason,
            }
        )
    return out
