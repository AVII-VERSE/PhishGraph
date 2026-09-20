"""Unit tests for Message Social-Engineering Analyzer."""

from app.analyzers.message_analyzer import MessageAnalyzer


def test_message_analyzer_detects_urgency_and_lockout():
    """Verify urgency, lockout, and time pressure lure detection."""
    analyzer = MessageAnalyzer()
    text = (
        "Your account has been locked due to suspicious activity. "
        "Verify immediately within 24 hours to prevent termination: "
        "https://security-verify.test/login"
    )

    res = analyzer.analyze_text(text)
    assert len(res.urls) == 1
    assert res.urls[0] == "https://security-verify.test/login"
    assert res.has_lure_signals is True
    assert any("urgency" in s.lower() for s in res.urgency_signals)
    assert any("lockout" in s.lower() for s in res.urgency_signals)
    assert any("time-window" in s.lower() for s in res.urgency_signals)


def test_message_analyzer_detects_claimed_brand_mismatch():
    """Verify mismatch between claimed brand in text and destination domain."""
    analyzer = MessageAnalyzer()
    text = (
        "Your PayPal account was accessed from an unrecognized device. "
        "Review your recent transactions here: https://paypa1-account-check.test/auth"
    )

    res = analyzer.analyze_text(text)
    assert "paypal" in res.claimed_brands
    assert res.brand_mismatch is True
    assert any("Claimed brand 'Paypal' does not match" in d for d in res.mismatched_brand_details)


def test_message_analyzer_legitimate_official_domain():
    """Verify no mismatch when message references official brand domain."""
    analyzer = MessageAnalyzer()
    text = "Please log in to your PayPal account at https://www.paypal.com/signin"

    res = analyzer.analyze_text(text)
    assert "paypal" in res.claimed_brands
    assert res.brand_mismatch is False
    assert len(res.mismatched_brand_details) == 0


def test_message_analyzer_no_lure_signals():
    """Verify benign text without phishing signals returns has_lure_signals=False."""
    analyzer = MessageAnalyzer()
    text = "Hey, let's meet up for coffee tomorrow afternoon."

    res = analyzer.analyze_text(text)
    assert res.has_lure_signals is False
    assert len(res.urls) == 0
    assert len(res.urgency_signals) == 0
