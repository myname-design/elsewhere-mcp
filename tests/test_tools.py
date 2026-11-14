import importlib
from unittest.mock import AsyncMock

import pytest


@pytest.mark.asyncio
async def test_feature_regressions(monkeypatch):
    monkeypatch.setenv("TRANSPORT", "stdio")
    monkeypatch.setenv("WINDY_API_KEY", "test-only")
    import server
    server = importlib.reload(server)
    fetch = AsyncMock(return_value={"webcams": [{
        "webcamId": "123", "status": "active",
        "location": {"country": "Japan"},
        "images": {"current": {"preview": "https://example.org/snapshot.jpg"}},
    }]})
    monkeypatch.setattr(server, "_get", fetch)
    assert (await server.search_nearby(35, 139))[0]["id"] == "123"
    assert (await server.search_by_country("jp"))[0]["country"] == "Japan"
    assert fetch.call_args.args[1]["countries"] == "JP"
    monkeypatch.setattr(server, "_mb_get", AsyncMock(return_value=[
        {"timestamp": "2026-01-01 12:00:00", "location_lat": "35", "location_long": "139"},
        {"timestamp": "2026-01-01 11:00:00", "location_lat": "34", "location_long": "138"},
    ]))
    monkeypatch.setattr(server, "_animal_info", AsyncMock(return_value={"name": "Bessie"}))
    track = await server.animal_track("study", "animal")
    assert track["count"] == 2
    assert track["points"][0]["lat"] == 34
    assert (await server.animal_latest("study", "animal"))["lat"] == 35
    # Cache fixture exercises the existing weather output without live API credentials.
    import time
    server._om_cache[(35, 139)] = (time.time(), {
        "timezone": "Asia/Tokyo", "utc_offset_seconds": 32400,
        "current": {"temperature_2m": 20, "weather_code": 0, "wind_direction_10m": 90},
    })
    weather = await server.weather_at(35, 139)
    assert weather["temperature_c"] == 20
    assert weather["weather"] == "晴"
    assert weather["wind_from"] == "东"
