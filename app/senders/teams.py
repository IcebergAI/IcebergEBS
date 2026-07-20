"""Microsoft Teams sender (#37).

A specialised webhook targeting a Teams *Workflows* incoming-webhook URL (the
successor to the retired Office 365 connectors). It POSTs an Adaptive Card wrapped
in the ``message``/``attachments`` envelope Teams expects, through the same
SSRF-pinned delivery as the generic webhook.
"""

from __future__ import annotations

from typing import Any, Mapping

from app.senders.base import AlertMessage, register_sender
from app.senders.content import event_facts
from app.senders.http import HttpJsonSender


class TeamsSender(HttpJsonSender):
    kind = "teams"
    label = "Microsoft Teams"
    target_label = "Teams workflow webhook URL"

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": "IcebergEBS alert", "weight": "Bolder", "size": "Medium"},
            {"type": "TextBlock", "text": message.text, "wrap": True},
            {
                "type": "FactSet",
                "facts": [{"title": label, "value": value} for label, value in event_facts(message)],
            },
        ]
        card: dict[str, Any] = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
        }
        if message.app_url:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "View in IcebergEBS", "url": message.app_url}]
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }


register_sender(TeamsSender())
