"""Authentik adapter (#32).

Authentik emits a standard OIDC ID token: ``sub``, ``email`` (+ ``email_verified``),
``name``, and ``groups`` (group names) when the scopes are configured. It's the
self-hostable end-to-end test target for the OIDC flow. Uses the shared
``StandardOIDCAdapter`` — no provider-specific claim quirks.
"""

from app.oidc.base import StandardOIDCAdapter, register_adapter

register_adapter(StandardOIDCAdapter("authentik"))
