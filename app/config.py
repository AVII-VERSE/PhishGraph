"""Application configuration management using Pydantic Settings."""

from functools import lru_cache
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """PhishGraph application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General
    APP_ENV: str = "development"
    APP_NAME: str = "PhishGraph"
    LOG_LEVEL: str = "INFO"

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_PROXY_URL: Optional[str] = None

    # Database & Cache
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishgraph.db"
    REDIS_URL: Optional[str] = None

    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # Network & SSRF Safety
    MAX_REDIRECTS: int = Field(default=10, ge=1, le=30)
    HTTP_TIMEOUT_SECONDS: float = Field(default=8.0, ge=1.0, le=60.0)
    MAX_RESPONSE_BYTES: int = Field(default=1048576, ge=1024, le=10485760)

    # Feature Toggles
    ENABLE_QR_SCAN: bool = True
    ENABLE_WATCHLIST: bool = True
    ENABLE_PDF_REPORTS: bool = True

    # Rate Limiting & Quotas (Section 39)
    RATE_LIMIT_SCANS_PER_WINDOW: int = Field(default=10, ge=1)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=600, ge=10)  # 10 minutes
    MAX_WATCHLIST_ENTRIES_PER_USER: int = Field(default=10, ge=1)
    MAX_URL_LENGTH: int = Field(default=2048, ge=64, le=8192)

    @property
    def is_sqlite(self) -> bool:
        """Return True if using SQLite database."""
        return "sqlite" in self.DATABASE_URL.lower()

    def get_safe_dict(self) -> dict[str, object]:
        """Return configuration dictionary with sensitive API keys and tokens redacted."""
        raw = self.model_dump()
        sensitive_keys = {
            "TELEGRAM_BOT_TOKEN",
            "VIRUSTOTAL_API_KEY",
            "OTX_API_KEY",
            "GOOGLE_SAFE_BROWSING_API_KEY",
            "ABUSEIPDB_API_KEY",
        }
        for key in sensitive_keys:
            val = raw.get(key)
            if val:
                raw[key] = f"***{str(val)[-4:]}" if len(str(val)) > 4 else "***"
            else:
                raw[key] = None
        return raw


def redact_secret(secret: Optional[str]) -> str:
    """Safely mask secrets for logging and user outputs."""
    if not secret:
        return "[NOT SET]"
    if len(secret) <= 6:
        return "***"
    return f"{secret[:2]}***{secret[-3:]}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
