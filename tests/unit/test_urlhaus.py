"""Unit tests for URLhaus Provider."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.threat_intel.urlhaus import URLhausProvider


@pytest.mark.asyncio
async def test_urlhaus_malicious_detection():
    """Verify parsing URLhaus match."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "id": "123456",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["Mozi", "elf"],
        "reporter": "abuse_hunter",
    }
    mock_client.post = AsyncMock(return_value=mock_resp)

    provider = URLhausProvider(http_client=mock_client)
    res = await provider.lookup_url("https://malware-drop.test/bin.exe")

    assert res.status == "success"
    assert res.malicious is True
    assert res.score >= 75
    assert any("malware_download" in lbl for lbl in res.labels)


@pytest.mark.asyncio
async def test_urlhaus_no_results():
    """Verify clean status when URLhaus has no records."""
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "no_results"}
    mock_client.post = AsyncMock(return_value=mock_resp)

    provider = URLhausProvider(http_client=mock_client)
    res = await provider.lookup_url("https://benign-site.test")

    assert res.status == "not_found"
    assert res.malicious is False
