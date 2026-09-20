"""Unit tests for structured logging and secret scrubbing."""

import json
import logging
from app.logging import JSONFormatter, SecretScrubber, scan_id_ctx, user_id_ctx


def test_secret_scrubber_masks_tokens():
    """Verify that SecretScrubber intercepts bot tokens and API keys."""
    scrubber = SecretScrubber()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Connecting using bot123456789:ABCdefGHI_secret and api_key='supersecrettoken123'",
        args=(),
        exc_info=None,
    )
    scrubber.filter(record)

    assert "bot123456789:ABCdefGHI_secret" not in record.msg
    assert "supersecrettoken123" not in record.msg
    assert "***REDACTED" in record.msg


def test_json_formatter_structure():
    """Verify JSONFormatter creates required schema with context variables."""
    scan_id_token = scan_id_ctx.set("SCAN-2026-TEST01")
    user_id_token = user_id_ctx.set(999)

    try:
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="phishgraph.test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=25,
            msg="Potential suspicious activity detected",
            args=(),
            exc_info=None,
        )
        record.event = "test_event"
        record.duration_ms = 42.5

        formatted_str = formatter.format(record)
        data = json.loads(formatted_str)

        assert data["level"] == "WARNING"
        assert data["message"] == "Potential suspicious activity detected"
        assert data["scan_id"] == "SCAN-2026-TEST01"
        assert data["user_id_internal"] == 999
        assert data["duration_ms"] == 42.5
        assert data["event"] == "test_event"
        assert "timestamp" in data
    finally:
        scan_id_ctx.reset(scan_id_token)
        user_id_ctx.reset(user_id_token)
