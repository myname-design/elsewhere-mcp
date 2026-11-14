"""Request diagnostics with fixed labels, never credentials or JWT claims."""
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar

from starlette.datastructures import Headers, MutableHeaders

auth_result = ContextVar("auth_result", default="not_checked")
logger = logging.getLogger("elsewhere.mcp")


def deployment_revision():
    """Render supplies this automatically; only expose a commit SHA, not env data."""
    value = os.getenv("RENDER_GIT_COMMIT", "")
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else None


class MCPDiagnosticsMiddleware:
    """Pure ASGI wrapper: no reading bodies or buffering SSE streams.

    Responses keep SDK status/error semantics. A scope hint helps OAuth clients
    select the required scope, and a generated ID correlates safe server logs.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/mcp":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        has_bearer = headers.get("authorization", "").lower().startswith("bearer ")
        origin = "present" if headers.get("origin") else "absent"
        method = scope["method"] if scope["method"] in {"GET", "POST", "DELETE", "OPTIONS"} else "other"
        request_id = uuid.uuid4().hex
        started = time.monotonic()
        context = auth_result.set("not_checked")

        async def send_response(message):
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request_id
                challenge = response_headers.get("www-authenticate", "")
                if message["status"] in {401, 403} and challenge.startswith("Bearer ") and 'scope="' not in challenge:
                    response_headers["WWW-Authenticate"] = challenge + ', scope="mcp:tools"'
                outcome = auth_result.get()
                if outcome == "not_checked" and not has_bearer:
                    outcome = "missing_bearer"
                logger.log(
                    logging.WARNING if message["status"] >= 400 else logging.INFO,
                    "mcp_http request_id=%s method=%s status=%d auth=%s origin=%s elapsed_ms=%d",
                    request_id, method, message["status"], outcome, origin,
                    int((time.monotonic() - started) * 1000),
                )
            await send(message)

        try:
            await self.app(scope, receive, send_response)
        finally:
            auth_result.reset(context)
