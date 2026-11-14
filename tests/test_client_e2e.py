"""Official MCP client against the production ASGI app, not direct tool calls.

JWT/JWKS validation, HTTP/SSE, initialization and all tool functions are real.
Only JWKS delivery and third-party data APIs use deterministic local fixtures.
No real OAuth grant, provider credentials, or GitHub writes occur here.
"""
import datetime as dt
import asyncio
import importlib
import json
import re
import socket
from contextlib import asynccontextmanager
from functools import partial
from types import SimpleNamespace

import httpx
import jsonschema
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from test_scalekit import RESOURCE, scalekit  # noqa: F401; shared signed-JWT fixture


CALLS = {
    "search_nearby": {"lat": 35, "lon": 139},
    "search_by_country": {"country": "JP"},
    "list_categories": {},
    "get_webcam": {"webcam_id": "123"},
    "look": {"webcam_id": "123"},
    "show": {"webcam_id": "123"},
    "where_sun_is": {},
    "list_studies": {},
    "list_animals": {"study_id": "study"},
    "animal_track": {"study_id": "study", "individual_id": "animal"},
    "animal_latest": {"study_id": "study", "individual_id": "animal"},
    "weather_at": {"lat": 35, "lon": 139},
}


@asynccontextmanager
async def production_client(app, bearer, network):
    headers = {"Authorization": "Bearer " + bearer}
    if not network:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), headers=headers) as client:
                yield client, RESOURCE
        return
    # Real TCP, real Uvicorn lifespan and real SSE parser, in addition to ASGI tests.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    runner = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False, lifespan="on"))
    task = asyncio.create_task(runner.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(10):
            while not runner.started:
                if task.done():
                    await task
                    raise AssertionError("Server stopped before startup")
                await asyncio.sleep(0.01)
        async with httpx.AsyncClient(headers=headers, trust_env=False) as client:
            yield client, f"http://127.0.0.1:{port}/mcp"
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, timeout=10)
        listener.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("network", [False, True], ids=["asgi", "tcp"])
async def test_official_client_discovers_and_calls_all_twelve(scalekit, monkeypatch, network):
    token, _ = scalekit
    import server
    server = importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    webcam = {"webcamId": "123", "title": "Test beach", "status": "active",
              "location": {"country": "Japan", "latitude": 35, "longitude": 139},
              "images": {"current": {"preview": "https://images.example/snapshot.jpg"}}}
    writes = []

    def upstream(request):
        host, path = request.url.host, request.url.path
        if host == "api.windy.com":
            if path.endswith("/categories"):
                return httpx.Response(200, json=[{"id": "beach"}])
            return httpx.Response(200, json=webcam if path.endswith("/123") else {"webcams": [webcam]})
        if host == "images.example":
            return httpx.Response(200, content=b"test-image-bytes", headers={"content-type": "image/jpeg"})
        if host == "api.github.com":
            assert request.method == "PUT"
            writes.append(json.loads(request.content))
            return httpx.Response(201, json={"commit": {"sha": "a" * 40}})
        if host == "www.movebank.org":
            entity = request.url.params["entity_type"]
            rows = {
                "study": f"id,name,taxon_ids,timestamp_last_deployed_location,i_have_download_access\nstudy,Test,Ciconia,{now},true\n",
                "individual": f"id,nick_name,taxon_canonical_name,timestamp_end\nanimal,Test bird,Ciconia,{now}\n",
                "event": f"timestamp,location_lat,location_long\n{now},35,139\n",
            }
            return httpx.Response(200, text=rows[entity])
        if host == "api.open-meteo.com":
            return httpx.Response(200, json={"timezone": "Asia/Tokyo", "current": {
                "temperature_2m": 20, "weather_code": 0, "time": now,
            }})
        raise AssertionError("Unexpected upstream request")

    # Patch only server's data client; the official MCP client still uses real ASGI transport.
    monkeypatch.setattr(server, "httpx", SimpleNamespace(AsyncClient=partial(
        httpx.AsyncClient, transport=httpx.MockTransport(upstream))))
    monkeypatch.setattr(server, "GH_TOKEN", "fixture-only")
    monkeypatch.setattr(server, "GH_REPO", "fixture/snapshots")
    monkeypatch.setattr(server, "MB_USER", "fixture-only")
    monkeypatch.setattr(server, "MB_PASS", "fixture-only")
    async with production_client(app, token(), network) as (http_client, url):
        async with streamable_http_client(url, http_client=http_client) as (read, write, session_id):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.capabilities.tools is not None
                assert session_id() is None  # no sticky worker/session required
                listed = await session.list_tools()
                assert {tool.name for tool in listed.tools} == set(CALLS)
                assert listed.nextCursor is None
                for tool in listed.tools:
                    assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", tool.name)
                    assert tool.description
                    assert tool.inputSchema["type"] == "object"
                    jsonschema.Draft202012Validator.check_schema(tool.inputSchema)
                    jsonschema.validate(CALLS[tool.name], tool.inputSchema)
                    assert tool.annotations.readOnlyHint == (tool.name != "show")
                    assert tool.annotations.destructiveHint is False
                    assert tool.meta["securitySchemes"] == [{"type": "oauth2", "scopes": ["mcp:tools"]}]
                    result = await session.call_tool(tool.name, CALLS[tool.name])
                    assert not result.isError, tool.name
                    assert result.content, tool.name
                    if tool.outputSchema:
                        jsonschema.Draft202012Validator.check_schema(tool.outputSchema)
                        jsonschema.validate(result.structuredContent, tool.outputSchema)
                assert len(writes) == 1  # show remains a write, but only to the fake API
                invalid = await session.call_tool("weather_at", {"lat": "not-a-number", "lon": 139})
                assert invalid.isError


@pytest.mark.asyncio
async def test_refreshed_access_token_without_transport_session(scalekit):
    """Simulates token replacement; does not claim to test Scalekit's refresh grant."""
    token, _ = scalekit
    import server
    importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), headers={
            "Authorization": "Bearer " + token({"jti": "first"}),
        }) as client:
            async with streamable_http_client(RESOURCE, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    assert len((await session.list_tools()).tools) == 12
                    client.headers["Authorization"] = "Bearer " + token({"jti": "replacement"})
                    assert len((await session.list_tools()).tools) == 12


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["2025-03-26", "2025-06-18", "2025-11-25"])
async def test_protocol_and_header_compatibility(scalekit, protocol):
    token, _ = scalekit
    import server
    importlib.reload(server)
    import asgi
    app = importlib.reload(asgi).app
    headers = {"authorization": "bearer " + token(),
               "Accept": "application/json, text/event-stream",
               "Origin": "https://example.onrender.com"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), headers=headers) as client:
            init = await client.post(RESOURCE, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": protocol, "capabilities": {},
                           "clientInfo": {"name": "protocol-test", "version": "1"}}})
            assert init.status_code == 200
            data = json.loads(next(line[6:] for line in init.text.splitlines() if line.startswith("data: ")))
            assert data["result"]["protocolVersion"] == protocol
            assert "mcp-session-id" not in init.headers
            client.headers["MCP-Protocol-Version"] = protocol
            listed = await client.post(RESOURCE, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert listed.status_code == 200
            data = json.loads(next(line[6:] for line in listed.text.splitlines() if line.startswith("data: ")))
            assert len(data["result"]["tools"]) == 12
            # Invalid headers remain rejected rather than weakening the transport.
            bad_accept = await client.post(RESOURCE, headers={"Accept": "application/json"}, json={})
            assert bad_accept.status_code == 406
            bad_type = await client.post(RESOURCE, headers={"Content-Type": "text/plain"}, content="{}")
            assert bad_type.status_code == 400
