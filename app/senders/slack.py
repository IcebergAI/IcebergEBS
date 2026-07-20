"""Slack sender (#37).

A specialised webhook: it POSTs to a Slack incoming-webhook URL (the same
SSRF-pinned delivery as the generic webhook) but renders Slack's message shape —
a fallback ``text`` plus a Block Kit section with the change facts. Works for
Slack-compatible endpoints (Mattermost, Rocket.Chat) that accept the same shape.
"""

from __future__ import annotations

from typing import Any, Mapping

from app.senders.base import AlertMessage, register_sender
from app.senders.content import event_facts
from app.senders.http import HttpJsonSender


class SlackSender(HttpJsonSender):
    kind = "slack"
    label = "Slack"
    target_label = "Slack incoming webhook URL"

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        detail = "\n".join(f"*{label}:* {value}" for label, value in event_facts(message))
        section_text = f"*{message.text}*\n{detail}"
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": section_text}},
        ]
        if message.app_url:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View in IcebergEBS"},
                            "url": message.app_url,
                        }
                    ],
                }
            )
        # ``text`` is the required notification/fallback string (used in previews).
        return {"text": message.text, "blocks": blocks}


register_sender(SlackSender())
