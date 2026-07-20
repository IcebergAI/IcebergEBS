"""Generic webhook sender (#37) + the canonical alert-payload shape (#168).

Generic webhook is one peer kind among the six — not a privileged base case. It
lives here alongside ``build_alert_payload`` because that function *is* the webhook
payload renderer, and keeping it in this pure module (rather than in
``notifications``) lets ``senders`` stay free of any import back into
``notifications`` (which imports ``senders`` for dispatch). ``notifications`` and
``routes/alerts`` re-import ``build_alert_payload`` from here.
"""

from __future__ import annotations

from typing import Any, Mapping

from app.config import settings
from app.senders.base import AlertMessage, register_sender
from app.senders.http import HttpJsonSender


def extension_deep_link(ext_id: int | None) -> str | None:
    """The IcebergEBS UI link for an extension, or ``None`` when no public base URL
    is configured. Single home so the webhook payload and the richer message kinds
    (Slack/Teams/ticketing) can't disagree on the link shape."""
    if not settings.app_base_url:
        return None
    return f"{settings.app_base_url.rstrip('/')}/extensions/{ext_id}"


def build_alert_payload(
    *,
    text: str,
    event: str,
    ext_id: int | None,
    name: str,
    store: str,
    store_url: str,
    old: Any,
    new: Any,
    risk_score: int | None,
) -> dict[str, Any]:
    """Assemble the webhook payload for an alert.

    The single source of the on-the-wire webhook shape, so the destination-test
    payload can't silently drift from what real alerts send — the "test" webhook is
    the real webhook by construction (#168). ``iceberg_ebs_url`` is included only
    when ``app_base_url`` is configured, exactly as real alerts do.
    """
    ext_payload: dict[str, Any] = {
        "id": ext_id,
        "name": name,
        "store": store,
        "store_url": store_url,
    }
    deep_link = extension_deep_link(ext_id)
    if deep_link is not None:
        ext_payload["iceberg_ebs_url"] = deep_link
    return {
        "text": text,
        "event": event,
        "extension": ext_payload,
        "change": {"old": old, "new": new},
        "risk_score": risk_score,
    }


class WebhookSender(HttpJsonSender):
    """Deliver the generic IcebergEBS JSON payload to an arbitrary webhook URL."""

    kind = "webhook"
    label = "Webhook"
    target_label = "Webhook URL"
    # config_fields defaults to () from HttpJsonSender — a generic webhook has none.

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        return build_alert_payload(
            text=message.text,
            event=message.event,
            ext_id=message.ext_id,
            name=message.name,
            store=message.store,
            store_url=message.store_url,
            old=message.old,
            new=message.new,
            risk_score=message.risk_score,
        )


register_sender(WebhookSender())
