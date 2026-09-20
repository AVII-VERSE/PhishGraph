"""Unit tests for AlienVault OTX Provider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.threat_intel.otx import AlienVaultOTXProvider


@pytest.mark.asyncio
async def test_otx_pulses_detected():
    """Verify OTX pulse parsing and detection flags."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "pulse_info": {
            "count": 3,
            "pulses": [
                {"name": "Phishing Campaign Targeting Banking Users"},
                {"name": "Known Credential Harvester Infrastructure"},
            ],
        }
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    provider = AlienVaultOTXProvider(api_key="mock_otx_key", http_client=mock_client)
    res = await provider.lookup_domain("phishing-target.test")

    assert res.status == "success"
    assert res.malicious is True
    assert res.score == 60
    assert len(res.labels) == 2


@pytest.mark.asyncio
async def test_otx_skipped_when_no_key():
    """Verify provider skips gracefully when key is absent."""
    provider = AlienVaultOTXProvider(api_key=None)
    res = await provider.lookup_url("https://example.com")
    assert res.status == "skipped_no_key"
