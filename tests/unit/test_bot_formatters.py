"""Unit tests for bot message formatters."""

from app.bot.formatters.scan_result import (
    format_generic_error,
    format_help_message,
    format_invalid_url_error,
    format_progress_message,
    format_scan_result,
    format_start_message,
)
from app.db.models.scan import Scan


def test_start_and_help_formatters():
    """Verify welcome and help message contents."""
    start_msg = format_start_message()
    assert "Welcome to PhishGraph" in start_msg
    assert "/help" in start_msg

    help_msg = format_help_message()
    assert "/analyze" in help_msg
    assert "/domain" in help_msg
    assert "/dns" in help_msg


def test_progress_formatter():
    """Verify progress message content."""
    msg = format_progress_message("SCAN-2026-TEST12", "phish.example")
    assert "SCAN-2026-TEST12" in msg
    assert "phish.example" in msg
    assert "Analyzing:" in msg


def test_scan_result_formatter():
    """Verify scan result message across risk tiers."""
    scan_crit = Scan(
        scan_uuid="SCAN-2026-CRIT01",
        original_url="https://fake-login.test",
        domain="fake-login.test",
        status="completed",
        risk_score=92.0,
        risk_level="CRITICAL",
        confidence_score=85.0,
    )
    res_crit = format_scan_result(scan_crit)
    assert "🚨" in res_crit
    assert "92/100" in res_crit
    assert "CRITICAL" in res_crit

    scan_low = Scan(
        scan_uuid="SCAN-2026-LOW01",
        original_url="https://legit-site.test",
        domain="legit-site.test",
        status="completed",
        risk_score=10.0,
        risk_level="LOW",
        confidence_score=90.0,
    )
    res_low = format_scan_result(scan_low)
    assert "🟢" in res_low
    assert "10/100" in res_low


def test_error_formatters():
    """Verify error messages do not leak internal tracebacks."""
    inv_msg = format_invalid_url_error("bad-url")
    assert "Invalid URL" in inv_msg
    assert "bad-url" in inv_msg

    gen_msg = format_generic_error("Connection timeout")
    assert "Analysis Error" in gen_msg
    assert "Connection timeout" in gen_msg
