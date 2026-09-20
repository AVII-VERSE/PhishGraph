"""Unit tests for Explainable Risk Scoring Engine."""

from datetime import datetime, timezone, timedelta
from app.analyzers.brand_analyzer import BrandImpersonationResult, BrandMatch
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.url_analyzer import analyze_url_heuristics
from app.scoring.risk_engine import calculate_risk_score
from app.threat_intel.base import ThreatIntelResult


def test_risk_score_clean_url():
    """Verify clean URL yields LOW risk with no factors."""
    heuristics = analyze_url_heuristics("https://example.com/about")
    res = calculate_risk_score(heuristics=heuristics)

    assert res.risk_score == 0.0
    assert res.risk_level == "LOW"
    assert len(res.factors) == 0


def test_risk_score_composite_critical():
    """Verify combined high-risk indicators push score into CRITICAL tier."""
    heuristics = analyze_url_heuristics("http://192.168.1.1/login/verify")

    # Domain registered 2 days ago
    rdap_res = DomainIntelligenceResult(
        domain="evil.test",
        domain_age_days=2,
        recently_registered=True,
    )

    # Malicious TI match
    ti_results = [
        ThreatIntelResult(
            provider="urlhaus",
            status="success",
            malicious=True,
            labels=["phishing"],
        )
    ]

    # Brand match
    brand_res = BrandImpersonationResult(
        domain="evil.test",
        has_brand_impersonation=True,
        matches=[
            BrandMatch(
                brand_name="paypal",
                similarity_score=0.95,
                detection_method="exact_keyword",
                is_official_domain=False,
            )
        ],
    )

    res = calculate_risk_score(
        heuristics=heuristics,
        rdap_res=rdap_res,
        ti_results=ti_results,
        brand_res=brand_res,
    )

    assert res.risk_score >= 75.0
    assert res.risk_level == "CRITICAL"
    assert len(res.factors) >= 4

    explanation = res.formatted_explanation
    assert "URLHAUS" in explanation
    assert "Paypal" in explanation
    assert "Domain registered" in explanation


def test_risk_score_capped_at_100():
    """Verify that multiple high weights never exceed 100 max."""
    heuristics = analyze_url_heuristics("http://192.168.1.1//login/verify/bank/secure")
    rdap_res = DomainIntelligenceResult(domain="evil.test", domain_age_days=1)
    ti_results = [
        ThreatIntelResult(provider="vt", status="success", malicious=True, labels=["phishing"]),
        ThreatIntelResult(provider="urlhaus", status="success", malicious=True),
    ]
    brand_res = BrandImpersonationResult(
        domain="evil.test",
        has_brand_impersonation=True,
        matches=[BrandMatch(brand_name="apple", similarity_score=0.9, is_official_domain=False)],
    )

    res = calculate_risk_score(
        heuristics=heuristics,
        rdap_res=rdap_res,
        ti_results=ti_results,
        brand_res=brand_res,
    )

    assert res.risk_score <= 100.0
