import importlib
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from security import JWTVerifier, remote_security


@pytest.fixture
def configured(monkeypatch):
    for key, value in {
        "WINDY_API_KEY": "test-only",
        "MCP_RESOURCE_URL": "https://example.onrender.com/mcp",
        "OAUTH_ISSUER_URL": "https://identity.example/",
        "OAUTH_JWKS_URL": "https://identity.example/jwks",
        "OAUTH_ALLOWED_SUBJECTS": "owner",
        "HOST": "0.0.0.0", "PORT": "10000", "TRANSPORT": "streamable-http",
    }.items():
        monkeypatch.setenv(key, value)


def test_fail_closed(configured, monkeypatch):
    monkeypatch.delenv("OAUTH_ALLOWED_SUBJECTS")
    with pytest.raises(ValueError, match="OAUTH_ALLOWED_SUBJECTS"):
        remote_security()


@pytest.mark.asyncio
async def test_jwt_validation(configured, monkeypatch):
    verifier = remote_security()["token_verifier"]
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(verifier.keys, "get_signing_key_from_jwt",
                        lambda _: SimpleNamespace(key=private.public_key()))
    now = int(time.time())
    claims = dict(iss=verifier.issuer, aud=verifier.resource, sub="owner",
                  iat=now, exp=now + 300, scope="mcp:tools")
    token = jwt.encode(claims, private, algorithm="RS256")
    assert (await verifier.verify_token(token)).subject == "owner"
    for changes in [
        {"iss": "https://wrong.example/"}, {"aud": "wrong"}, {"sub": "stranger"},
        {"exp": now - 1}, {"iat": now + 100}, {"scope": ["mcp:tools"]},
    ]:
        assert await verifier.verify_token(jwt.encode(claims | changes, private, algorithm="RS256")) is None
    assert await verifier.verify_token(jwt.encode(claims, other, algorithm="RS256")) is None
    assert await verifier.verify_token("malformed") is None


@pytest.mark.asyncio
async def test_http_and_tools(configured, monkeypatch):
    import server
    server = importlib.reload(server)
    assert server.mcp.settings.host == "0.0.0.0"
    assert server.mcp.settings.port == 10000
    names = {tool.name for tool in await server.mcp.list_tools()}
    assert names == {
        "search_nearby", "search_by_country", "list_categories", "get_webcam",
        "look", "show", "where_sun_is", "list_studies", "list_animals",
        "animal_latest", "animal_track", "weather_at",
    }
    app = server.mcp.streamable_http_app()
    verifier = server.mcp._token_verifier
    from mcp.server.auth.provider import AccessToken
    async def verify(token):
        if token in {"valid", "no-scope"}:
            return AccessToken(token=token, client_id="owner", expires_at=int(time.time()) + 60,
                               scopes=["mcp:tools"] if token == "valid" else [],
                               resource="https://example.onrender.com/mcp")
        return None
    monkeypatch.setattr(verifier, "verify_token", verify)
    async with server.mcp.session_manager.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://example.onrender.com") as client:
            assert (await client.get("/healthz")).status_code == 200
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.json()["resource"] == "https://example.onrender.com/mcp"
            for method in ["GET", "POST", "DELETE"]:
                response = await client.request(method, "/mcp")
                assert response.status_code == 401
                assert "resource_metadata" in response.headers["www-authenticate"]
            assert (await client.post("/mcp", headers={"Authorization": "Bearer invalid"})).status_code == 401
            assert (await client.post("/mcp", headers={"Authorization": "Bearer no-scope"})).status_code == 403
            headers = {"Authorization": "Bearer valid", "Accept": "application/json, text/event-stream"}
            response = await client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1"}},
            })
            assert response.status_code == 200
            assert "serverInfo" in response.text
            assert (await client.post("/mcp", headers=headers | {"Origin": "https://evil.example"}, json={})).status_code == 403
