"""Unit tests for TLS Certificate Analyzer."""

import datetime
from app.analyzers.tls_analyzer import TLSAnalysisResult, parse_asn1_date


def test_parse_asn1_date():
    """Verify parsing various OpenSSL certificate date formats."""
    parsed = parse_asn1_date("Sep 20 18:00:00 2026 GMT")
    assert parsed is not None
    assert parsed.year == 2026
    assert parsed.month == 9

    parsed_iso = parse_asn1_date("20260920180000Z")
    assert parsed_iso is not None
    assert parsed_iso.year == 2026


def test_tls_analysis_result_flags():
    """Verify signal evaluation on TLS results."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # Valid certificate
    res_valid = TLSAnalysisResult(
        domain="example.com",
        https_available=True,
        is_valid=True,
        hostname_matches=True,
        common_name="example.com",
        issuer="CN=Let's Encrypt Authority",
        valid_until=now + datetime.timedelta(days=60),
        days_remaining=60,
    )
    assert res_valid.is_valid is True
    assert res_valid.is_expired is False

    # Expired certificate
    res_expired = TLSAnalysisResult(
        domain="expired.example",
        https_available=True,
        is_valid=False,
        hostname_matches=True,
        is_expired=True,
        days_remaining=-10,
        signals=["TLS Certificate has expired"],
    )
    assert res_expired.is_expired is True
    assert any("expired" in s for s in res_expired.signals)

    # Self-signed certificate
    res_self = TLSAnalysisResult(
        domain="selfsigned.example",
        https_available=True,
        is_valid=False,
        is_self_signed=True,
        signals=["Self-signed TLS certificate detected"],
    )
    assert res_self.is_self_signed is True
    assert any("Self-signed" in s for s in res_self.signals)
