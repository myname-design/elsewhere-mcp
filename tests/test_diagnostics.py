import asyncio
import importlib
import logging
import re

import httpx
import pytest

from diagnostics import auth_result
from test_scalekit import RESOURCE, scalekit  # noqa: F401


@pytest.mark.asyncio
async def test_failure_categories_are_private_and_request_scoped(scalekit, caplog):
    token, _ = scalekit
    import server
    importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    caplog.set_level(logging.INFO, logger="elsewhere.mcp")
    cases = [
        ({"iss": "https://wrong.example/private-issuer"}, "issuer_mismatch", 401),
        ({"aud": "private-audience"}, "audience_mismatch", 401),
        ({"sub": "private-user"}, "subject_not_allowed", 401),
        ({"exp": 1}, "expired_token", 401),
        ({"nbf": 4102444800}, "token_not_yet_valid", 401),
        ({"scope": []}, "invalid_scope_claim", 401),
        ({"scope": "other-private-scope"}, "insufficient_scope", 403),
    ]
    tokens = []
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
            async def request(changes, reason, expected):
                bearer = token(changes)
                tokens.append(bearer)
                response = await client.post(RESOURCE, headers={"Authorization": "Bearer " + bearer}, json={})
                assert response.status_code == expected
                assert 'scope="mcp:tools"' in response.headers["www-authenticate"]
                assert "resource_metadata=" in response.headers["www-authenticate"]
                if expected == 401:
                    assert reason not in response.text
                request_id = response.headers["x-request-id"]
                assert re.fullmatch(r"[a-f0-9]{32}", request_id)
                assert f"request_id={request_id}" in caplog.text
                assert any(f"request_id={request_id}" in r.message and f"auth={reason}" in r.message
                           for r in caplog.records)
            await asyncio.gather(*(request(*case) for case in cases))
            response = await client.post(RESOURCE, json={})
            assert response.status_code == 401
            assert "auth=missing_bearer" in caplog.text
    assert auth_result.get() == "not_checked"
    assert all(secret not in caplog.text for secret in tokens)
    for secret in ["private-issuer", "private-audience", "private-user", "other-private-scope"]:
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_verified_origin_remains_restricted(scalekit, caplog):
    token, _ = scalekit
    import server
    importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    caplog.set_level(logging.INFO, logger="elsewhere.mcp")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
            response = await client.post(RESOURCE, headers={
                "Authorization": "Bearer " + token(), "Origin": "https://chatgpt.com",
            }, json={})
            assert response.status_code == 403
            assert "auth=verified origin=present" in caplog.text
            assert "www-authenticate" not in response.headers  # transport rejection, not OAuth


@pytest.mark.asyncio
async def test_health_reports_only_valid_deployment_revision(scalekit, monkeypatch):
    import server
    importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://example.onrender.com") as client:
        monkeypatch.setenv("RENDER_GIT_COMMIT", "a" * 40)
        assert (await client.get("/healthz")).json() == {"status": "ok", "revision": "a" * 40}
        monkeypatch.setenv("RENDER_GIT_COMMIT", "not-a-sha-do-not-expose")
        assert (await client.get("/healthz")).json() == {"status": "ok"}
