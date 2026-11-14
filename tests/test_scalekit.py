"""Scalekit-shaped JWTs through real PyJWT/JWKS and FastMCP middleware.

Only the outbound JWKS HTTP response is mocked; no real credentials are used.
"""
import importlib
import io
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from security import remote_security

RESOURCE = "https://example.onrender.com/mcp"
AUDIENCE = "res_test_resource"
ISSUER = "https://test.scalekit.com/resources/" + AUDIENCE
JWKS = "https://test.scalekit.com/keys"


@pytest.fixture
def scalekit(monkeypatch):
    for name, value in {
        "WINDY_API_KEY": "test-only", "TRANSPORT": "streamable-http",
        "MCP_RESOURCE_URL": RESOURCE, "OAUTH_ISSUER_URL": ISSUER,
        "OAUTH_JWKS_URL": JWKS, "OAUTH_AUDIENCE": AUDIENCE,
        "OAUTH_ALLOWED_SUBJECTS": "owner,second-owner",
    }.items():
        monkeypatch.setenv(name, value)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid="current", use="sig", alg="RS256")
    requests = []

    def jwks_response(opener, request, **kwargs):
        assert request.full_url == JWKS
        requests.append(request.full_url)
        return io.BytesIO(json.dumps({"keys": [jwk]}).encode())

    monkeypatch.setattr("urllib.request.OpenerDirector.open", jwks_response)

    def token(changes=None, omit=(), signing_key=None):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": [AUDIENCE, RESOURCE], "sub": "owner",
            "iat": now, "exp": now + 300, "scope": "mcp:tools",
            "client_id": "m2m_test_client",
        }
        claims.update(changes or {})
        for name in omit:
            claims.pop(name, None)
        return jwt.encode(claims, signing_key or private, algorithm="RS256", headers={"kid": "current"})

    return token, requests


@pytest.mark.asyncio
async def test_scalekit_audience_and_jwks(scalekit):
    token, requests = scalekit
    verifier = remote_security()["token_verifier"]
    for audience in (AUDIENCE, [AUDIENCE], [AUDIENCE, RESOURCE]):
        result = await verifier.verify_token(token({"aud": audience}))
        assert result is not None
        assert result.resource == RESOURCE
        assert result.subject == "owner"
        assert result.client_id == "m2m_test_client"
        assert result.scopes == ["mcp:tools"]
    assert requests == [JWKS]  # Actual PyJWKClient parses and caches public keys.
    assert await verifier.verify_token(token({"sub": "second-owner"})) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [
    {"iss": "https://test.scalekit.com"},
    {"iss": ISSUER + "/"},
    {"iss": "https://test.scalekit.com/resources/res_other"},
    {"aud": RESOURCE},  # Never fall back to URL once res_... is configured.
    {"aud": ["res_other", RESOURCE]},
    {"sub": "unauthorized"},
    {"sub": ""},
    {"exp": 1},
    {"iat": 4102444800},
    {"nbf": 4102444800},
    {"scope": ["mcp:tools"]},
])
async def test_reject_wrong_claims(scalekit, changes):
    token, _ = scalekit
    assert await remote_security()["token_verifier"].verify_token(token(changes)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "exp", "iat"])
async def test_required_claims(scalekit, missing):
    token, _ = scalekit
    assert await remote_security()["token_verifier"].verify_token(token(omit=[missing])) is None


@pytest.mark.asyncio
async def test_signature_algorithm_and_jwks_failure(scalekit, monkeypatch, caplog):
    token, _ = scalekit
    verifier = remote_security()["token_verifier"]
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    invalid = token(signing_key=other)
    assert await verifier.verify_token(invalid) is None
    hmac_token = jwt.encode({"iss": ISSUER}, "test-only-secret-for-rejection-32bytes", algorithm="HS256",
                            headers={"kid": "current"})
    assert await verifier.verify_token(hmac_token) is None

    def unavailable(*args, **kwargs):
        from urllib.error import URLError
        raise URLError("test outage")

    monkeypatch.setattr("urllib.request.OpenerDirector.open", unavailable)
    assert await remote_security()["token_verifier"].verify_token(token()) is None
    assert invalid not in caplog.text
    assert hmac_token not in caplog.text


@pytest.mark.parametrize("audience", ["", " ", "res_one,res_two", "res_one res_two"])
def test_invalid_audience_configuration(scalekit, monkeypatch, audience):
    monkeypatch.setenv("OAUTH_AUDIENCE", audience)
    with pytest.raises(ValueError, match="OAUTH_AUDIENCE"):
        remote_security()


def test_url_audience_backwards_compatibility(scalekit, monkeypatch):
    monkeypatch.delenv("OAUTH_AUDIENCE")
    assert remote_security()["token_verifier"].audience == RESOURCE


def test_user_allowlist_remains_required(scalekit, monkeypatch):
    monkeypatch.setenv("OAUTH_ALLOWED_SUBJECTS", ", ,")
    with pytest.raises(ValueError, match="OAUTH_ALLOWED_SUBJECTS"):
        remote_security()


@pytest.mark.asyncio
async def test_authenticated_http_discovery_and_tools(scalekit):
    token, _ = scalekit
    import server
    server = importlib.reload(server)
    # Exercise the actual Render import target, including its own lifespan.
    import asgi
    app = importlib.reload(asgi).app
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://example.onrender.com") as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}
            canonical = await client.get("/.well-known/oauth-protected-resource/mcp")
            root = await client.get("/.well-known/oauth-protected-resource")
            assert root.status_code == canonical.status_code == 200
            assert root.json() == canonical.json()
            assert root.json()["resource"] == RESOURCE
            assert root.json()["authorization_servers"] == [ISSUER]
            assert root.json()["scopes_supported"] == ["mcp:tools"]
            assert root.json()["bearer_methods_supported"] == ["header"]
            assert canonical.history == root.history == health.history == []
            assert (await client.options("/.well-known/oauth-protected-resource")).status_code == 204
            # We are a resource server, not a second/partially implemented AS.
            assert (await client.get("/.well-known/oauth-authorization-server")).status_code == 404
            for method in ("GET", "POST", "DELETE"):
                response = await client.request(method, "/mcp")
                assert response.status_code == 401
                assert "/.well-known/oauth-protected-resource/mcp" in response.headers["www-authenticate"]
            assert (await client.get("/mcp", params={"access_token": token()})).status_code == 401
            base_headers = {"Accept": "application/json, text/event-stream"}
            async def rpc(method, params, bearer):
                return await client.post("/mcp", headers=base_headers | {"Authorization": "Bearer " + bearer},
                                         json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})

            for bad in ({"sub": "stranger"}, {"iss": "https://test.scalekit.com"}, {"aud": RESOURCE}):
                assert (await rpc("tools/list", {}, token(bad))).status_code == 401
            for scope in ("", "mcp:tools:read", "other"):
                assert (await rpc("tools/list", {}, token({"scope": scope}))).status_code == 403
            assert (await rpc("tools/list", {}, token(omit=["scope"]))).status_code == 403
            initialized = await rpc("initialize", {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "scalekit-test", "version": "1"},
            }, token())
            assert initialized.status_code == 200 and "serverInfo" in initialized.text
            listed = await rpc("tools/list", {}, token())
            assert listed.status_code == 200
            tools = await server.mcp.list_tools()
            assert len(tools) == 12
            assert all(tool.name in listed.text for tool in tools)
            server._om_cache[(35, 139)] = (time.time(), {
                "current": {"temperature_2m": 20}, "timezone": "Asia/Tokyo",
            })
            called = await rpc("tools/call", {"name": "weather_at", "arguments": {"lat": 35, "lon": 139}}, token())
            assert called.status_code == 200 and "temperature_c" in called.text
            for header in ({"Origin": "https://evil.example"}, {"Host": "evil.example"}):
                rejected = await client.post("/mcp", headers=base_headers | header | {
                    "Authorization": "Bearer " + token()}, json={})
                assert rejected.status_code in (403, 421)


@pytest.mark.asyncio
async def test_python_entrypoint_serves_complete_root_router(scalekit, monkeypatch):
    import server
    import uvicorn
    server = importlib.reload(server)
    captured = {}
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "10000")
    server = importlib.reload(server)

    def capture_run(app, **kwargs):
        captured.update(app=app, **kwargs)

    monkeypatch.setattr(uvicorn, "run", capture_run)
    server.main()
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 10000
    app = captured["app"]
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://example.onrender.com") as client:
            assert (await client.get("/healthz")).status_code == 200
            response = await client.get("/mcp")
            assert response.status_code == 401
            # Follow the actual advertised discovery URL, rather than assume a path.
            import re
            metadata_url = re.search(r'resource_metadata="([^"]+)"', response.headers["www-authenticate"])[1]
            metadata = await client.get(metadata_url)
            assert metadata.status_code == 200
            assert metadata.json()["authorization_servers"] == [ISSUER]
            # The app must not have been mounted a second time under /mcp.
            assert (await client.get("/mcp/mcp")).status_code == 404
            assert (await client.get("/mcp/healthz")).status_code == 404


def test_stdio_cannot_be_exposed_as_unauthenticated_http(scalekit, monkeypatch):
    import server
    monkeypatch.setenv("TRANSPORT", "stdio")
    server = importlib.reload(server)
    with pytest.raises(RuntimeError, match="TRANSPORT=streamable-http"):
        server.create_http_app()
    calls = []
    monkeypatch.setattr(server.mcp, "run", lambda **kwargs: calls.append(kwargs))
    server.main()
    assert calls == [{"transport": "stdio"}]


@pytest.mark.parametrize("entrypoint", ["script", "uvicorn"])
def test_running_production_entrypoints(scalekit, entrypoint):
    # Exercise a real listener and ASGI lifespan in a fresh interpreter.
    # No tokens are sent, so no JWKS/third-party network calls are needed.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = dict(os.environ, HOST="127.0.0.1", PORT=str(port),
               GH_TOKEN="", GH_REPO="", MOVEBANK_USER_B64="", MOVEBANK_PASS_B64="")
    command = [sys.executable, "server.py"] if entrypoint == "script" else [
        sys.executable, "-m", "uvicorn", "asgi:app",
        "--host", "127.0.0.1", "--port", str(port),
    ]
    process = subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=1, trust_env=False) as client:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, "HTTP process exited before becoming ready"
                try:
                    health = client.get("/healthz")
                    break
                except httpx.TransportError:
                    assert time.monotonic() < deadline, "HTTP process did not become ready"
                    time.sleep(0.05)
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}
            for path in ("/.well-known/oauth-protected-resource",
                         "/.well-known/oauth-protected-resource/mcp"):
                response = client.get(path)
                assert response.status_code == 200
                assert response.json()["authorization_servers"] == [ISSUER]
                assert response.json()["resource"] == RESOURCE
            challenge = client.get("/mcp")
            assert challenge.status_code == 401
            assert "resource_metadata=" in challenge.headers["www-authenticate"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
