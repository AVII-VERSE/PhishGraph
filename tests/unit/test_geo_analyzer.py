"""Unit tests for GeoIPAnalyzer and country flag resolution."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.analyzers.geo_analyzer import GeoIPAnalyzer, country_code_to_flag


def test_country_code_to_flag():
    """Verify ISO country codes map to correct Unicode flag emojis."""
    assert country_code_to_flag("US") == "🇺🇸"
    assert country_code_to_flag("IN") == "🇮🇳"
    assert country_code_to_flag("GB") == "🇬🇧"
    assert country_code_to_flag("") == "🌐"
    assert country_code_to_flag("XYZ") == "🌐"


@pytest.mark.asyncio
async def test_geoip_private_ip():
    """Verify private and loopback IPs are identified as internal."""
    analyzer = GeoIPAnalyzer()
    res = await analyzer.lookup("127.0.0.1")
    assert res.country == "Private/Internal Network"
    assert res.flag_emoji == "🔒"


@pytest.mark.asyncio
async def test_geoip_mocked_public_ip():
    """Verify parsing of public IP geolocation metadata."""
    analyzer = GeoIPAnalyzer()
    mock_json = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "California",
        "city": "San Francisco",
        "isp": "Cloudflare, Inc.",
        "org": "Cloudflare, Inc.",
        "as": "AS13335 Cloudflare, Inc.",
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_json

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        res = await analyzer.lookup("104.16.123.96")
        assert res.country == "United States"
        assert res.flag_emoji == "🇺🇸"
        assert res.city == "San Francisco"
        assert "Cloudflare" in res.isp
