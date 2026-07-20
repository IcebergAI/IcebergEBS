"""Outbound alert delivery adapters (#37).

Importing this package registers every sender kind (each module self-registers on
import, like the OIDC adapters). Registration order here fixes the order kinds are
listed in the API/UI. Webhook is first only because it is the behaviour-preserving
baseline kind — not a privileged one.
"""

# Import each adapter module for its register_sender side effect (display order is
# fixed by _KIND_ORDER in base.py, so these can sort however the linter prefers).
from app.senders import email, slack, teams, tickets, webhook  # noqa: F401
from app.senders.base import (
    AlertMessage,
    AlertSender,
    ConfigField,
    DestinationConfigError,
    SenderError,
    all_senders,
    get_sender,
    kind_descriptors,
    register_sender,
    sender_kinds,
)

__all__ = [
    "AlertMessage",
    "AlertSender",
    "ConfigField",
    "DestinationConfigError",
    "SenderError",
    "all_senders",
    "get_sender",
    "kind_descriptors",
    "register_sender",
    "sender_kinds",
]
