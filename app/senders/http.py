"""Shared HTTP-POST delivery core for alert senders (#37).

``HttpJsonSender`` is the ``StandardOIDCAdapter`` analogue of this package: it owns
"POST a rendered JSON body to the destination URL through the SSRF-pinned request
machinery", and a concrete kind is just a payload renderer plus its config-field
declarations. Webhook, Slack and Teams are peer subclasses that differ only in
``render_payload``; Jira/ServiceNow additionally override ``request_headers`` /
``endpoint_url`` (see ``app/senders/tickets.py``).

Every kind built on this core inherits, for free, the whole webhook defence:
SSRF validation at create/update time and again at send time, DNS-rebinding IP
pinning, disabled redirects, proxy routing via the shared client's transport, and
the deliberate no-retry-on-POST rule (``app/webhooks.py`` / ``fetchers/transport.py``).
"""

from __future__ import annotations

from typing import Any, Mapping

from urllib.parse import urlparse

import httpx

from app.senders.base import AlertMessage, ConfigField, DestinationConfigError, SenderError
from app.webhooks import WebhookValidationError, send_pinned_request, validate_webhook_url


class HttpJsonSender:
    """Concrete base for every HTTP-based sender kind. Subclasses set the class
    attributes and override ``render_payload`` (and optionally the hooks below)."""

    kind: str = ""
    label: str = ""
    target_label: str = "Webhook URL"
    config_fields: tuple[ConfigField, ...] = ()
    # Credential-bearing kinds (ticketing) set this so an http:// target — which would
    # send the Authorization header in plaintext to the wire / outbound proxy — is
    # refused at both create/update and send time (bot review). Webhook/Slack/Teams
    # carry no request credentials, so http is permitted for them as before.
    require_https: bool = False

    # --- hooks a subclass overrides -------------------------------------------

    def render_payload(self, message: AlertMessage, config: Mapping[str, str]) -> dict[str, Any]:
        """The on-the-wire JSON body for ``message``. The one thing a peer kind
        (webhook/slack/teams) actually differs in. ``config`` is available for kinds
        whose body depends on it (e.g. Jira's project key); most ignore it."""
        raise NotImplementedError

    def request_headers(self, config: Mapping[str, str]) -> dict[str, str]:
        """Extra request headers (e.g. Authorization). Default: none."""
        return {}

    def endpoint_url(self, target: str, config: Mapping[str, str]) -> str:
        """The URL to POST to, derived from the stored ``target`` (default: the
        target verbatim — a webhook URL). Ticketing kinds append an API path."""
        return target

    def validate_config(self, config: Mapping[str, str]) -> None:
        """Validate kind-specific config (default: nothing). Raise
        ``DestinationConfigError`` on a problem."""
        return None

    def availability(self) -> tuple[bool, str | None]:
        return (True, None)

    # --- shared implementation ------------------------------------------------

    def _needs_https(self, url: str) -> bool:
        return self.require_https and urlparse(url).scheme != "https"

    async def validate(self, target: str, config: Mapping[str, str]) -> None:
        url = self.endpoint_url(target, config)
        if self._needs_https(url):
            raise DestinationConfigError(
                f"{self.label} destinations must use an https:// URL — the API "
                "credential would otherwise be sent in plaintext"
            )
        try:
            await validate_webhook_url(url)
        except WebhookValidationError as exc:
            # WebhookValidationError messages are static + user-facing by design.
            raise DestinationConfigError(str(exc)) from exc
        self.validate_config(config)

    async def send(
        self,
        client: httpx.AsyncClient,
        target: str,
        config: Mapping[str, str],
        message: AlertMessage,
    ) -> None:
        url = self.endpoint_url(target, config)
        # Defence in depth: refuse a plaintext credential send even for a row that
        # predates the create-time guard (or was written straight to the DB).
        if self._needs_https(url):
            raise SenderError(f"{self.label} delivery requires https:// (credentials must not be sent in plaintext)")
        payload = self.render_payload(message, config)
        headers = self.request_headers(config)
        resp = await send_pinned_request(client, url, json=payload, headers=headers or None)
        resp.raise_for_status()
