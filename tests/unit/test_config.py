"""Unit tests for configuration management."""

import pytest
from pydantic import ValidationError
from app.config import Settings, redact_secret


def test_default_settings():
    """Verify default settings initialization."""
    settings = Settings(
        DATABASE_URL="sqlite+aiosqlite:///./test.db",
        TELEGRAM_BOT_TOKEN="123456789:ABCdefGHI_jklMNO",
        VIRUSTOTAL_API_KEY="vt_secret_api_key_12345",
    )
    assert settings.APP_NAME == "PhishGraph"
    assert settings.MAX_REDIRECTS == 10
    assert settings.HTTP_TIMEOUT_SECONDS == 8.0
    assert settings.is_sqlite is True


def test_redact_secret():
    """Verify secret masking function."""
    assert redact_secret(None) == "[NOT SET]"
    assert redact_secret("") == "[NOT SET]"
    assert redact_secret("short") == "***"
    assert redact_secret("secret12345") == "se***345"


def test_safe_dict_masks_secrets():
    """Verify that get_safe_dict() suppresses all sensitive credentials."""
    settings = Settings(
        DATABASE_URL="sqlite+aiosqlite:///./test.db",
        TELEGRAM_BOT_TOKEN="bot123456:ABC-DEF-GHI",
        VIRUSTOTAL_API_KEY="very_secret_vt_key",
        OTX_API_KEY="very_secret_otx_key",
        GOOGLE_SAFE_BROWSING_API_KEY="gsb_key_xyz",
        ABUSEIPDB_API_KEY="abuse_key_123",
    )
    safe_data = settings.get_safe_dict()

    assert safe_data["TELEGRAM_BOT_TOKEN"] == "***-GHI"
    assert safe_data["VIRUSTOTAL_API_KEY"] == "***_key"
    assert safe_data["OTX_API_KEY"] == "***_key"
    assert safe_data["GOOGLE_SAFE_BROWSING_API_KEY"] == "***_xyz"
    assert safe_data["ABUSEIPDB_API_KEY"] == "***_123"


def test_redirect_limit_validation():
    """Verify validation boundaries for network limits."""
    with pytest.raises(ValidationError):
        Settings(MAX_REDIRECTS=0)  # ge=1

    with pytest.raises(ValidationError):
        Settings(MAX_REDIRECTS=50)  # le=30
