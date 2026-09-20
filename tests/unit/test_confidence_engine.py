"""Unit tests for Evidence Confidence Scoring Engine."""

from datetime import datetime, timezone
from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.scoring.confidence_engine import calculate_confidence_score
from app.threat_intel.base import ThreatIntelResult


def test_confidence_baseline():
    """Verify default baseline confidence when minimal data is available."""
    conf = calculate_confidence_score()
    assert conf >= 20.0


def test_confidence_comprehensive_evidence():
    """Verify confidence score reaches high tier when all independent sources corroborate."""
    dns_res = DNSAnalysisResult(domain="example.com", resolved_ips=["93.184.216.34"])
    rdap_res = DomainIntelligenceResult(
        domain="example.com",
        created_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    tls_res = TLSAnalysisResult(domain="example.com", https_available=True, is_valid=True)
    redir_res = RedirectChainResult(
        initial_url="https://example.com",
        final_url="https://example.com",
        total_hops=0,
    )
    ti_results = [
        ThreatIntelResult(provider="prov1", status="success", malicious=True),
        ThreatIntelResult(provider="prov2", status="success", malicious=True),
    ]

    conf = calculate_confidence_score(
        dns_res=dns_res,
        rdap_res=rdap_res,
        tls_res=tls_res,
        redir_res=redir_res,
        ti_results=ti_results,
    )

    assert conf >= 85.0
    assert conf <= 100.0
