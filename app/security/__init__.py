"""Security package for PhishGraph."""

from app.security.url_safety import is_ip_allowed, validate_url_safety

__all__ = ["is_ip_allowed", "validate_url_safety"]
