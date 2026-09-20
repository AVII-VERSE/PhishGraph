"""Unit tests for RDAP Domain Intelligence Analyzer."""

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.analyzers.domain_analyzer import analyze_domain_rdap, calculate_age_and_signals


def test_calculate_age_and_signals():
    """Verify calculation of domain age and risk signals."""
    now = datetime.now(timezone.utc)

    # Very new domain (<7 days old)
    created_new = now - timedelta(days=3)
    age, _, rec_reg, _, signals = calculate_age_and_signals(created_new, None, None)
    assert age == 3
    assert rec_reg is True
    assert any("HIGH RISK" in s for s in signals)

    # Established domain (300 days old)
    created_old = now - timedelta(days=300)
    age_old, _, rec_reg_old, _, signals_old = calculate_age_and_signals(created_old, None, None)
    assert age_old == 300
    assert rec_reg_old is False
    assert len(signals_old) == 0


@pytest.mark.asyncio
async def test_domain_rdap_mocked_response():
    """Verify parsing RDAP JSON payload."""
    mock_rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-09-15T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-09-15T12:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]],
            }
        ],
        "nameservers": [{"ldhName": "DNS1.REGISTRAR-SERVERS.COM"}],
        "status": ["active"],
    }

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_rdap
    mock_client.get = AsyncMock(return_value=mock_resp)

    res = await analyze_domain_rdap("brand-secure-test.com", http_client=mock_client)

    assert res.domain == "brand-secure-test.com"
    assert res.created_date is not None
    assert res.registrar == "NameCheap, Inc."
    assert "dns1.registrar-servers.com" in res.nameservers
    assert res.recently_registered is True
