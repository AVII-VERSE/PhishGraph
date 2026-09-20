"""Unit tests for Google Safe Browsing Provider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.threat_intel.safebrowsing import GoogleSafeBrowsingProvider


@pytest.mark.asyncio
async def test_safebrowsing_match_detected():
    """Verify Google Safe Browsing detection match."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
            }
        ]
    }
    mock_client.post = AsyncMock(return_value=mock_resp)

    provider = GoogleSafeBrowsingProvider(api_key="mock_gsb_key", http_client=mock_client)
    res = await provider.lookup_url("http://deceptive-login.test")

    assert res.status == "success"
    assert res.malicious is True
    assert "SOCIAL_ENGINEERING" in res.labels


@pytest.mark.asyncio
async def test_safebrowsing_no_match():
    """Verify clean status when no threats are found."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}
    mock_client.post = AsyncMock(return_value=mock_resp)

    provider = GoogleSafeBrowsingProvider(api_key="mock_gsb_key", http_client=mock_client)
    res = await provider.lookup_url("https://safe-portal.test")

    assert res.status == "not_found"
    assert res.malicious is False
