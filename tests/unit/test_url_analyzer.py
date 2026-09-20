"""Unit tests for URL Heuristics Analyzer."""

from app.analyzers.url_analyzer import analyze_url_heuristics, calculate_shannon_entropy


def test_shannon_entropy():
    """Verify entropy calculations."""
    # Repeated single character has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0

    # Normal dictionary word has moderate entropy
    word_ent = calculate_shannon_entropy("login")
    assert 2.0 <= word_ent <= 3.0

    # High randomness string has high entropy
    rand_ent = calculate_shannon_entropy("a8D93kLmP01xZ77qW")
    assert rand_ent > 3.8


def test_url_heuristics_clean_url():
    """Verify benign URL heuristics."""
    features = analyze_url_heuristics("https://example.com/about")
    assert features.hostname == "example.com"
    assert features.is_ip_hostname is False
    assert features.has_at_symbol is False
    assert features.has_punycode is False
    assert features.subdomain_count == 0
    assert len(features.suspicious_keywords_found) == 0


def test_url_heuristics_suspicious_patterns():
    """Verify detection of suspicious keywords, symbols, and IP hostname."""
    url = "http://admin@192.168.1.50//secure-bank-login/verify?token=12345"
    features = analyze_url_heuristics(url)

    assert features.is_ip_hostname is True
    assert features.has_at_symbol is True
    assert features.has_double_slash_in_path is True
    assert "login" in features.suspicious_keywords_found
    assert "verify" in features.suspicious_keywords_found
    assert "bank" in features.suspicious_keywords_found
    assert "secure" in features.suspicious_keywords_found

    assert any("IP-address" in s for s in features.heuristic_signals)
    assert any("@ symbol" in s for s in features.heuristic_signals)
    assert any("Consecutive slashes" in s for s in features.heuristic_signals)


def test_url_heuristics_punycode():
    """Verify punycode xn-- detection."""
    features = analyze_url_heuristics("https://xn--pypal-4ve.com/account")
    assert features.has_punycode is True
    assert any("Punycode" in s for s in features.heuristic_signals)
