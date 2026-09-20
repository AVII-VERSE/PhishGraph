"""Unit tests for VirusTotal Provider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.threat_intel.virustotal import VirusTotalProvider


@pytest.mark.asyncio
async def test_virustotal_skipped_no_key():
    """Verify provider returns skipped_no_key when API key is empty."""
    vt = VirusTotalProvider(api_key=None)
    res = await vt.lookup_url("https://example.com")
    assert res.status == "skipped_no_key"
    assert res.malicious is False


@pytest.mark.asyncio
async def test_virustotal_malicious_detection():
    """Verify parsing of malicious engine tally."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 70},
                "categories": {"Google Safe Browsing": "phishing", "Kaspersky": "malicious"},
            }
        }
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    vt = VirusTotalProvider(api_key="test_key", http_client=mock_client)
    res = await vt.lookup_url("https://phishing-site.test/login")

    assert res.status == "success"
    assert res.malicious is True
    assert res.score > 50
    assert any("phishing" in lbl for lbl in res.labels)


@pytest.mark.asyncio
async def test_virustotal_not_found():
    """Verify 404 response translates to not_found status."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404
    mock_client.get = AsyncMock(return_value=mock_resp)

    vt = VirusTotalProvider(api_key="test_key", http_client=mock_client)
    res = await vt.lookup_url("https://brand-new-unknown-url.test")
    assert res.status == "not_found"
    assert res.malicious is False
