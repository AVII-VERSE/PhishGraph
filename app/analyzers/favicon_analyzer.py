"""Favicon Analyzer module.

Fetches and hashes web application favicons safely with SSRF controls,
size limits, and timeouts.
"""

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional
import httpx
import mmh3

from app.security.url_safety import validate_url_safety

logger = logging.getLogger(__name__)

MAX_FAVICON_SIZE = 512 * 1024  # 512 KB
FAVICON_TIMEOUT = 5.0  # seconds


@dataclass
class FaviconResult:
    """Favicon hash results and metadata."""

    favicon_url: Optional[str] = None
    mmh3_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    content_length: int = 0
    content_type: Optional[str] = None
    error: Optional[str] = None


class FaviconAnalyzer:
    """Analyzes and hashes remote website favicons."""

    def __init__(self, timeout: float = FAVICON_TIMEOUT, max_size: int = MAX_FAVICON_SIZE) -> None:
        self.timeout = timeout
        self.max_size = max_size

    async def analyze(
        self,
        domain: str,
        custom_url: Optional[str] = None,
        allow_private_in_testing: bool = False,
    ) -> FaviconResult:
        """Fetch favicon for domain and return computed hashes.

        Args:
            domain: Target domain or hostname.
            custom_url: Explicit favicon URL if discovered (e.g. from HTML).
            allow_private_in_testing: Bypass SSRF check in test environment.

        Returns:
            FaviconResult with mmh3 and sha256 hashes.
        """
        urls_to_try = []
        if custom_url:
            urls_to_try.append(custom_url)
        else:
            urls_to_try.extend([
                f"https://{domain}/favicon.ico",
                f"http://{domain}/favicon.ico",
            ])

        last_error = None
        for target_url in urls_to_try:
            try:
                # 1. Enforce strict SSRF check
                is_safe, reason, _ = await validate_url_safety(
                    target_url, allow_private_in_testing=allow_private_in_testing
                )
                if not is_safe:
                    logger.warning("Favicon fetch blocked by SSRF filter for %s: %s", target_url, reason)
                    return FaviconResult(favicon_url=target_url, error=f"SSRF validation blocked: {reason}")

                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    verify=False,  # Allow inspection of suspicious/self-signed certs
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGraph/1.0"},
                ) as client:
                    response = await client.get(target_url)

                if response.status_code != 200:
                    last_error = f"HTTP {response.status_code}"
                    continue

                content = response.content
                if not content:
                    last_error = "Empty response"
                    continue

                if len(content) > self.max_size:
                    return FaviconResult(
                        favicon_url=target_url,
                        error=f"Favicon exceeded max size limit of {self.max_size} bytes",
                    )

                # Shodan standard mmh3 uses base64 encoded bytes
                b64_encoded = base64.encodebytes(content)
                raw_mmh3 = mmh3.hash(b64_encoded)
                mmh3_str = f"mmh3:{raw_mmh3}"
                sha256_str = f"sha256:{hashlib.sha256(content).hexdigest()}"

                return FaviconResult(
                    favicon_url=target_url,
                    mmh3_hash=mmh3_str,
                    sha256_hash=sha256_str,
                    content_length=len(content),
                    content_type=response.headers.get("Content-Type"),
                )
            except httpx.RequestError as e:
                logger.debug("Favicon request failed for %s: %s", target_url, e)
                last_error = str(e)
            except Exception as e:
                logger.debug("Unexpected error fetching favicon for %s: %s", target_url, e)
                last_error = str(e)

        return FaviconResult(
            favicon_url=urls_to_try[0] if urls_to_try else None,
            error=last_error or "Favicon not found",
        )
