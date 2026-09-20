"""Unit tests for Punycode and Homograph Analyzer."""

from app.analyzers.punycode_analyzer import analyze_punycode_and_homographs


def test_clean_ascii_domain():
    """Verify standard ASCII domain passes without homoglyph warnings."""
    res = analyze_punycode_and_homographs("google.com")
    assert res.is_punycode is False
    assert res.is_mixed_script is False
    assert res.unicode_domain is None


def test_punycode_decoding():
    """Verify punycode xn-- domain is correctly parsed and decoded."""
    # xn--apple-43d.com decodes to applе.com (with cyrillic e)
    res = analyze_punycode_and_homographs("xn--apple-43d.com")
    assert res.is_punycode is True
    assert res.unicode_domain is not None
    assert "appl" in res.unicode_domain
    assert res.is_mixed_script is True
    assert "Greek" in res.scripts_detected
    assert "Latin" in res.scripts_detected
    assert any("Mixed-script" in s for s in res.signals)
