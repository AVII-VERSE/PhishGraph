"""Unit tests for Asynchronous DNS Analyzer."""

from unittest.mock import AsyncMock, MagicMock
import dns.resolver
import pytest
from app.analyzers.dns_analyzer import analyze_dns


def create_mock_rdata(val: str, address: str = None):
    rdata = MagicMock()
    rdata.__str__.return_value = val
    if address:
        rdata.address = address
    return rdata


@pytest.mark.asyncio
async def test_dns_analyzer_with_records():
    """Verify DNS record parsing with mocked responses."""
    mock_resolver = MagicMock()

    async def mock_resolve(domain, rtype):
        mock_answers = MagicMock()
        mock_answers.rrset = MagicMock(ttl=300)

        if rtype == "A":
            r1 = create_mock_rdata("93.184.216.34", "93.184.216.34")
            mock_answers.__iter__.return_value = [r1]
            return mock_answers
        elif rtype == "NS":
            r1 = create_mock_rdata("ns1.example.com.")
            mock_answers.__iter__.return_value = [r1]
            return mock_answers
        elif rtype == "MX":
            r1 = create_mock_rdata("10 mail.example.com.")
            mock_answers.__iter__.return_value = [r1]
            return mock_answers
        else:
            raise dns.resolver.NoAnswer()

    mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

    res = await analyze_dns("example.com", resolver=mock_resolver)

    assert res.domain == "example.com"
    assert "93.184.216.34" in res.resolved_ips
    assert "ns1.example.com" in res.nameservers
    assert "mail.example.com" in res.mx_hosts
    assert res.has_a_record is True
    assert res.has_mx_record is True


@pytest.mark.asyncio
async def test_dns_analyzer_nxdomain():
    """Verify clean handling of NXDOMAIN without throwing exceptions."""
    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    res = await analyze_dns("nonexistent-domain-12345.test", resolver=mock_resolver)

    assert res.domain == "nonexistent-domain-12345.test"
    assert len(res.records) == 0
    assert res.has_a_record is False
    assert any("No A or AAAA" in s for s in res.signals)
