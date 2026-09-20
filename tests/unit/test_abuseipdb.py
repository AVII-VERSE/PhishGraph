"""Unit tests for AbuseIPDB Provider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.threat_intel.abuseipdb import AbuseIPDBProvider


@pytest.mark.asyncio
async def test_abuseipdb_high_confidence():
    """Verify high abuse confidence score marks malicious."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "198.51.100.25",
            "abuseConfidenceScore": 85,
            "totalReports": 42,
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Malicious Hosting Ltd",
            "countryCode": "RU",
        }
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    provider = AbuseIPDBProvider(api_key="mock_key", http_client=mock_client)
    res = await provider.lookup_ip("198.51.100.25")

    assert res.status == "success"
    assert res.malicious is True
    assert res.score == 85
    assert any("85%" in lbl for lbl in res.labels)


@pytest.mark.asyncio
async def test_abuseipdb_skipped_when_no_key():
    """Verify provider skips when no key is set."""
    provider = AbuseIPDBProvider(api_key=None)
    res = await provider.lookup_ip("8.8.8.8")
    assert res.status == "skipped_no_key"
