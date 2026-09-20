"""Unit tests for ASN Analyzer."""

from unittest.mock import AsyncMock, MagicMock
import pytest
from app.analyzers.asn_analyzer import ASNAnalyzer


@pytest.mark.asyncio
async def test_asn_analyzer_private_ip():
    """Verify private/loopback IPs are rejected immediately without DNS queries."""
    analyzer = ASNAnalyzer()
    assert await analyzer.lookup_ip_asn("127.0.0.1") is None
    assert await analyzer.lookup_ip_asn("192.168.1.1") is None
    assert await analyzer.lookup_ip_asn("10.0.0.1") is None


@pytest.mark.asyncio
async def test_asn_analyzer_mocked_success():
    """Verify ASN parsing from Team Cymru DNS TXT record."""
    analyzer = ASNAnalyzer()

    mock_rdata = MagicMock()
    mock_rdata.strings = [b"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"]

    mock_answer = [mock_rdata]
    analyzer.resolver.resolve = AsyncMock(return_value=mock_answer)

    asn = await analyzer.lookup_ip_asn("8.8.8.8")
    assert asn == "AS15169"


@pytest.mark.asyncio
async def test_asn_analyzer_dns_error():
    """Verify ASN analyzer handles DNS resolution exceptions cleanly."""
    analyzer = ASNAnalyzer()
    analyzer.resolver.resolve = AsyncMock(side_effect=Exception("DNS query timeout"))

    asn = await analyzer.lookup_ip_asn("8.8.8.8")
    assert asn is None
