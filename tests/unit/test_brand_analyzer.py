"""Unit tests for Brand Impersonation and Typosquatting Analyzer."""

from app.analyzers.brand_analyzer import (
    BrandAnalyzer,
    jaro_winkler_similarity,
    levenshtein_distance,
    normalize_leetspeak,
)


def test_levenshtein_distance():
    """Verify Levenshtein distance calculations."""
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("apple", "aple") == 1
    assert levenshtein_distance("google", "g00gle") == 2


def test_jaro_winkler_similarity():
    """Verify Jaro-Winkler string similarity."""
    assert jaro_winkler_similarity("paypal", "paypal") == 1.0
    assert jaro_winkler_similarity("apple", "xyz") < 0.2
    assert jaro_winkler_similarity("apple", "orange") < 0.6


def test_normalize_leetspeak():
    """Verify leetspeak substitutions."""
    assert normalize_leetspeak("paypa1") == "paypal"
    assert normalize_leetspeak("micros0ft") == "microsoft"
    assert normalize_leetspeak("b@nk") == "bank"


def test_brand_analyzer_official_domain():
    """Verify official brand domains are recognized and not marked as impersonation."""
    analyzer = BrandAnalyzer()
    res = analyzer.analyze_domain("paypal.com")

    assert res.has_brand_impersonation is False
    assert len(res.matches) == 1
    assert res.matches[0].is_official_domain is True


def test_brand_analyzer_exact_keyword_spoof():
    """Verify keyword presence in non-official domains is caught."""
    analyzer = BrandAnalyzer()
    res = analyzer.analyze_domain("paypal-account-security-update.com")

    assert res.has_brand_impersonation is True
    assert res.top_matched_brand == "paypal"
    assert any("Contains 'paypal'" in s for s in res.signals)


def test_brand_analyzer_leetspeak_typosquatting():
    """Verify typosquatted leetspeak domains are caught."""
    analyzer = BrandAnalyzer()
    res = analyzer.analyze_domain("paypa1-login.test")

    assert res.has_brand_impersonation is True
    assert res.top_matched_brand == "paypal"


def test_brand_analyzer_fuzzy_similarity():
    """Verify edit-distance typosquatting detection."""
    analyzer = BrandAnalyzer()
    res = analyzer.analyze_domain("paypai.com")

    assert res.has_brand_impersonation is True
    assert res.top_matched_brand == "paypal"
