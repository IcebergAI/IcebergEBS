"""CSRF defence-in-depth: an Origin/Referer check on state-changing browser
requests (#107).

This layers *on top of* the deliberate SameSite=Lax + JSON-only-API posture (#16);
it does not replace it. Every non-safe method is checked **except** Bearer-token
(M2M) requests, which carry no ambient cookie credential and have no browser Origin —
so the JSON API's primary credential is unaffected. Crucially the check is NOT gated
on an existing session cookie: the unauthenticated ``POST /login`` establishes the
cookie, so a cookie-only gate would leave login CSRF open. Same-origin requests work
with no configuration; ``trusted_origins`` is an escape hatch for proxy hops that
rewrite Host so the app-observed origin differs from the browser's.
"""

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _is_bearer_auth(request: Request) -> bool:
    return request.headers.get("authorization", "").lower().startswith("bearer ")


def _request_origin(request: Request) -> str | None:
    """The request's stated origin as ``scheme://host``, from Origin or (fallback) Referer."""
    origin = request.headers.get("origin")
    if origin:
        return origin
    referer = request.headers.get("referer")
    if referer:
        parts = urlsplit(referer)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


def origin_allowed(origin: str, request: Request, trusted_origins: frozenset[str]) -> bool:
    """True if ``origin`` is this request's own origin or an explicitly trusted one."""
    expected = f"{request.url.scheme}://{request.url.netloc}"
    return origin == expected or origin in trusted_origins


class CSRFOriginMiddleware(BaseHTTPMiddleware):
    """Reject a state-changing browser request whose Origin/Referer doesn't match the
    request host (or a configured trusted origin). Bearer-token requests are exempt."""

    def __init__(self, app: ASGIApp, trusted_origins: list[str] | None = None) -> None:
        super().__init__(app)
        self.trusted_origins = frozenset(trusted_origins or [])

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method not in _SAFE_METHODS and not _is_bearer_auth(request):
            # Every non-safe, non-Bearer request is origin-checked — including the
            # unauthenticated POST /login that mints the session cookie, so login CSRF
            # is covered too. Bearer M2M requests carry no browser Origin and are exempt.
            origin = _request_origin(request)
            if origin is None or not origin_allowed(origin, request, self.trusted_origins):
                return JSONResponse({"detail": "Origin check failed"}, status_code=403)
        return await call_next(request)
