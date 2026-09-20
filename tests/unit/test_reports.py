"""Unit tests for HTML and PDF Report Generators."""

from app.reports.report_generator import generate_html_report, generate_pdf_report


def _get_sample_scan_data() -> dict:
    """Generate sample structured scan dictionary for report compilation."""
    return {
        "scan": {
            "id": 1,
            "scan_uuid": "SCAN-2026-TEST01",
            "original_url": "https://secure-login.example/auth",
            "domain": "secure-login.example",
            "status": "completed",
            "risk_score": 88.0,
            "risk_level": "HIGH",
            "confidence_score": 92.0,
        },
        "dns_records": [
            {"record_type": "A", "name": "secure-login.example", "value": "198.51.100.25", "ttl": 300},
            {"record_type": "NS", "name": "secure-login.example", "value": "ns1.badinfra.test", "ttl": 86400},
        ],
        "tls_record": {
            "issuer": "Let's Encrypt Authority X3",
            "subject": "secure-login.example",
            "serial_number": "1234567890ABCDEF",
            "tls_version": "TLSv1.3",
        },
        "redirects": [
            {"hop_number": 1, "source_url": "https://secure-login.example/auth", "destination_url": "https://secure-login.example/creds", "status_code": 302}
        ],
        "threat_intel": [
            {"provider": "virustotal", "provider_status": "success", "provider_score": 14, "labels": "phishing, malware"},
            {"provider": "urlhaus", "provider_status": "success", "provider_score": 100, "labels": "malicious"},
        ],
        "risk_factors": [
            {"factor_code": "TI_MALICIOUS", "factor_description": "Flagged malicious by threat intel feeds", "weight": 35.0, "evidence_source": "threat_intel"},
            {"factor_code": "BRAND_SPOOF", "factor_description": "Possible impersonation of brand PayPal", "weight": 25.0, "evidence_source": "brand_analyzer"},
        ],
        "fingerprint": {
            "asn": "AS64500",
            "registrar": "Example Registrar LLC",
            "favicon_hash": "mmh3:998877",
        },
        "correlations": [
            {"target_scan_id": 99, "correlation_score": 75, "relationship_types": ["SAME_FAVICON_HASH", "SAME_NAMESERVER"]}
        ],
    }


def test_generate_html_report():
    """Verify HTML report includes all primary sections and badges."""
    data = _get_sample_scan_data()
    html = generate_html_report(data)

    assert "SCAN-2026-TEST01" in html
    assert "https://secure-login.example/auth" in html
    assert "HIGH RISK" in html
    assert "Contributing Risk Factors" in html
    assert "Threat Intelligence Feeds" in html
    assert "Resolved DNS Infrastructure" in html
    assert "Campaign Infrastructure Correlations" in html
    assert "PhishGraph Defensive Cybersecurity Platform" in html


def test_generate_pdf_report():
    """Verify PDF generator produces valid binary PDF data."""
    data = _get_sample_scan_data()
    pdf_bytes = generate_pdf_report(data)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
