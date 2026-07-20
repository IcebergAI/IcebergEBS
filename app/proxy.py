"""Outbound-proxy resolution for the shared httpx client (#216).

One pure helper, :func:`resolve_proxy_url`, turns the admin-managed
``ProxySettings`` row (or its cached snapshot) into a routing decision for a
given target URL: the proxy URL to use, or ``None`` for a direct connection.
Three modes:

- ``SYSTEM``   — honour the environment proxy vars (``HTTP(S)_PROXY`` /
  ``ALL_PROXY`` / ``NO_PROXY``). Unlike deep_thought's implementation this
  cannot be delegated to httpx via ``trust_env``: the shared client is built
  with a custom ``transport=``, and httpx never applies env proxies in that
  case. So the env vars are parsed here, with the same bypass semantics as
  EXPLICIT mode. The default.
- ``NONE``     — always a direct connection.
- ``EXPLICIT`` — route through the configured ``proxy_url`` unless the target
  host matches the no-proxy exclusion list (standard ``NO_PROXY`` semantics),
  in which case go direct.

The bypass decision is made per target URL because a single httpx client
serves every egress path (store fetchers, package downloads, webhook
delivery); ``ProxyRoutingTransport`` (app/fetchers/transport.py) consults
:func:`route_for` on each request. Proxy credentials are a secret: they live
only in the environment (``ICEBERG_EBS_PROXY_USERNAME`` / ``_PASSWORD``), are
injected into the proxy URL at resolution time, and are never persisted on
the DB row, returned by the API, or logged.

Routing is read from an in-memory snapshot (``get_config`` / ``set_config``)
refreshed at startup and whenever an admin saves (single-process — the
deployment mandates one uvicorn worker). A ``None`` snapshot means "not
loaded" and every request goes direct — in production that state cannot be
reached (the lifespan fails startup if the config can't load, so an EXPLICIT
deployment can never silently fail open); it exists for tests and tooling
that exercise the transport without the app lifecycle.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address, ip_network
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from app.config import Settings, settings


class ProxyMode(StrEnum):
    """How outbound HTTP connections are routed."""

    NONE = "NONE"
    SYSTEM = "SYSTEM"
    EXPLICIT = "EXPLICIT"


PROXY_MODES = ("none", "system", "explicit")
# No SOCKS: httpx would need the optional socks extra (a runtime dependency the
# production image doesn't carry). Corporate HTTP(S) proxies are the target;
# widen here (+ pyproject `httpx[socks]` + uv lock) if SOCKS is ever needed.
PROXY_URL_SCHEMES = ("http", "https")


@dataclass(frozen=True)
class ProxyConfig:
    """Immutable snapshot of the routing config (no secret — creds are env-only)."""

    mode: str = ProxyMode.SYSTEM.value
    proxy_url: str = ""
    no_proxy: str = ""


# In-memory routing snapshot. ``None`` means "not loaded" — every request goes
# direct. Production never runs in this state (startup fails if the config
# can't load); it exists for tests/tooling without the app lifecycle.
_config: ProxyConfig | None = None


def get_config() -> ProxyConfig | None:
    return _config


def set_config(cfg: ProxyConfig | None) -> None:
    global _config
    _config = cfg


def resolve_proxy_url(cfg: ProxyConfig, url: str) -> str | None:
    """The proxy URL for an outbound request to ``url``, or ``None`` for direct.

    ``cfg`` may be a :class:`ProxyConfig` snapshot or a ``ProxySettings`` row —
    only ``.mode`` / ``.proxy_url`` / ``.no_proxy`` are read. The returned URL
    carries the env-only credentials, so it must never be logged.
    """
    try:
        mode = ProxyMode(str(cfg.mode).upper())
    except ValueError:
        mode = ProxyMode.SYSTEM
    if mode is ProxyMode.SYSTEM:
        return _system_proxy_for(url)
    if mode is ProxyMode.EXPLICIT and cfg.proxy_url:
        host = urlsplit(url).hostname
        if _should_bypass(host, _parse_no_proxy(cfg.no_proxy)):
            return None
        return _with_credentials(cfg.proxy_url)
    # NONE, or EXPLICIT with no proxy URL configured → direct connection.
    return None


def route_for(url: str) -> str | None:
    """``resolve_proxy_url`` against the cached snapshot; direct when unloaded."""
    cfg = get_config()
    return resolve_proxy_url(cfg, url) if cfg is not None else None


def _system_proxy_for(url: str) -> str | None:
    """SYSTEM mode: the environment's proxy for ``url``, or ``None`` for direct.

    Follows the curl/httpx conventions — ``https_proxy`` for https targets,
    ``http_proxy`` for http, ``all_proxy`` as the fallback, each in lower- and
    uppercase, with ``no_proxy`` applied through the same parser as EXPLICIT
    mode. No credential injection: an env proxy URL may carry its own userinfo.
    """
    parsed = urlsplit(url)
    host = parsed.hostname
    if _should_bypass(host, _parse_no_proxy(_env_first("no_proxy") or "")):
        return None
    names = ("https_proxy",) if parsed.scheme == "https" else ("http_proxy",)
    proxy = _env_first(*names, "all_proxy")
    return proxy or None


def _env_first(*names: str) -> str:
    """First non-empty value among ``names``, checking lower- then uppercase."""
    for name in names:
        for candidate in (name, name.upper()):
            value = os.environ.get(candidate, "").strip()
            if value:
                return value
    return ""


def _parse_no_proxy(value: str) -> list[str]:
    return [t.strip() for t in (value or "").split(",") if t.strip()]


def _should_bypass(host: str | None, entries: list[str]) -> bool:
    """Standard NO_PROXY match: ``*`` bypasses all; a CIDR matches an IP host in
    range; a domain matches the host and its subdomains; an IP/host matches
    exactly. An unknown host goes direct."""
    if not host:
        return True
    host = host.lower()
    try:
        ip = ip_address(host)
    except ValueError:
        ip = None
    for entry in entries:
        if entry == "*":
            return True
        if "/" in entry and ip is not None:
            try:
                if ip in ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
            continue
        target = entry.lower().lstrip(".")
        if host == target or host.endswith("." + target):
            return True
    return False


def _with_credentials(proxy_url: str) -> str:
    """Inject the env-only proxy credentials into the proxy URL's userinfo."""
    if not settings.proxy_username:
        return proxy_url
    parsed = urlsplit(proxy_url)
    if not parsed.hostname:
        return proxy_url
    userinfo = quote(settings.proxy_username, safe="")
    password = settings.proxy_password.get_secret_value()
    if password:
        userinfo += ":" + quote(password, safe="")
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{userinfo}@{parsed.hostname}{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def validate_proxy_settings(s: Settings | None = None) -> None:
    """Fail fast at startup on malformed proxy env config.

    Never logs or echoes the URL — a hand-rolled ``ICEBERG_EBS_PROXY_URL`` may
    carry credentials in the userinfo.
    """
    s = s or settings
    mode = s.proxy_mode.strip().lower()
    if mode not in PROXY_MODES:
        raise RuntimeError(f"ICEBERG_EBS_PROXY_MODE must be one of {'|'.join(PROXY_MODES)}, got {s.proxy_mode!r}.")
    if mode == "explicit" and not s.proxy_url.strip():
        raise RuntimeError("ICEBERG_EBS_PROXY_MODE=explicit requires ICEBERG_EBS_PROXY_URL to be set.")
    if s.proxy_url.strip():
        parsed = urlsplit(s.proxy_url.strip())
        if parsed.scheme not in PROXY_URL_SCHEMES or not parsed.hostname:
            raise RuntimeError(
                "ICEBERG_EBS_PROXY_URL must be an absolute URL with scheme "
                f"{'|'.join(PROXY_URL_SCHEMES)} and a host (e.g. http://proxy.corp:3128)."
            )
        if parsed.username or parsed.password:
            # The URL seeds the admin-editable DB row and is echoed by the API —
            # userinfo there would break the env-only credential guarantee.
            raise RuntimeError(
                "ICEBERG_EBS_PROXY_URL must not contain credentials — set "
                "ICEBERG_EBS_PROXY_USERNAME / ICEBERG_EBS_PROXY_PASSWORD instead."
            )


_URL_USERINFO_RE = re.compile(r"(?<=://)[^/@\s]+(?=@)")


def _redact_secret(text: str, secret: str, *, decoded: bool = False) -> str:
    """Replace every spelling of ``secret`` in ``text`` with ``***``.

    scrub() runs inside every egress error handler, so it must never raise on
    hostile input. ``quote()``/``unquote()`` can fail on pathological values —
    a proxy env var may carry surrogate-escaped bytes (invalid UTF-8 decoded by
    ``os.environ`` via ``surrogateescape``, e.g. ``\\udcff``), which ``urlsplit``
    accepts but ``quote`` rejects with ``UnicodeEncodeError``. A spelling that
    can't be built is skipped; the raw form is always redacted. ``str.replace``
    is total on any ``str``.

    ``decoded`` also redacts the ``unquote`` spelling — used **only** for env-URL
    userinfo, which urlsplit keeps percent-encoded while an exception message may
    carry the decoded form. It is deliberately **not** applied to the explicit
    credentials: unquoting a %-shaped credential (e.g. ``%2F`` → ``/``) would
    inject a structural char whose replacement could dismantle URL syntax and
    disable the generic backstop (#228 review). scrub() also runs that backstop
    first, so it can never be undone by a later secret-form replacement.
    """
    if not secret:
        return text
    forms = [secret]
    builders = [lambda s: quote(s, safe="")]
    if decoded:
        builders.append(unquote)
    for build in builders:
        try:
            forms.append(build(secret))
        except (UnicodeError, ValueError):
            continue
    for form in forms:
        text = text.replace(form, "***")
    return text


def scrub(text: str) -> str:
    """Redact any credential the exception text may have echoed back.

    httpx exception messages can embed the proxy URL, and the resolved URL
    carries credentials — never let the raw string reach a log line or a
    persisted error column. Three layers (#228):

    - the explicit ``ICEBERG_EBS_PROXY_USERNAME``/``_PASSWORD`` values (raw and
      %-quoted), the EXPLICIT-mode credentials;
    - userinfo carried inside the proxy env vars themselves — in SYSTEM mode
      (the default) the resolved proxy URL is the raw ``HTTP(S)_PROXY``/
      ``ALL_PROXY`` value, whose embedded credentials the settings-based pass
      cannot see;
    - a generic ``scheme://user:pass@`` strip as the backstop for any other URL
      userinfo the message may carry.

    The generic backstop runs **first**, so no later secret-form replacement (a
    decoded credential can collapse to a structural char like ``/``) can dismantle
    the ``://…@`` syntax it relies on and disable it (#228 review). Every credential
    spelling is then redacted through :func:`_redact_secret`, which keeps scrub()
    total against hostile env input (malformed URLs, surrogate escapes) — the
    sanitizer in an error path must not itself raise.
    """
    # Generic backstop first (see above) — it can't be undone by a later pass.
    text = _URL_USERINFO_RE.sub("***", text)
    # Explicit EXPLICIT-mode credentials: raw + %-quoted only (no decoded form).
    for secret in (settings.proxy_password.get_secret_value(), settings.proxy_username):
        text = _redact_secret(text, secret)
    # SYSTEM-mode env userinfo: urlsplit keeps it percent-encoded, but a message
    # may carry the decoded spelling too — include it (decoded=True).
    for env_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        raw = os.environ.get(env_name, "").strip()
        if not raw:
            continue
        try:
            parsed = urlsplit(raw)
        except ValueError:
            # A malformed proxy env value (e.g. the unterminated IPv6 literal
            # ``http://[``) makes urlsplit raise ValueError. Skip this var's
            # userinfo pass — the backstop above already redacted URL userinfo.
            continue
        for env_secret in (parsed.password, parsed.username):
            if env_secret:
                text = _redact_secret(text, env_secret, decoded=True)
    return text
