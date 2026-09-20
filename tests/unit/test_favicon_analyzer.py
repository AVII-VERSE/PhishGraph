"""Unit tests for Favicon Analyzer."""

from unittest.mock import AsyncMock, patch
import httpx
import pytest
from app.analyzers.favicon_analyzer import FaviconAnalyzer, FaviconResult


@pytest.mark.asyncio
async def test_favicon_analyzer_success():
    """Verify favicon analyzer retrieves and hashes content correctly."""
    analyzer = FaviconAnalyzer()
    sample_content = b"\x00\x00\x01\x00sample-favicon-ico-bytes"

    mock_resp = httpx.Response(
        200,
        content=sample_content,
        headers={"Content-Type": "image/x-icon"},
        request=httpx.Request("GET", "https://example.test/favicon.ico"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await analyzer.analyze(
            domain="example.test",
            allow_private_in_testing=True,
        )

        assert isinstance(result, FaviconResult)
        assert result.mmh3_hash is not None
        assert result.mmh3_hash.startswith("mmh3:")
        assert result.sha256_hash is not None
        assert result.sha256_hash.startswith("sha256:")
        assert result.content_length == len(sample_content)
        assert result.error is None


@pytest.mark.asyncio
async def test_favicon_analyzer_size_limit():
    """Verify analyzer aborts if favicon payload exceeds maximum size."""
    analyzer = FaviconAnalyzer(max_size=100)  # Low 100-byte limit
    oversized_content = b"A" * 500

    mock_resp = httpx.Response(
        200,
        content=oversized_content,
        request=httpx.Request("GET", "https://example.test/favicon.ico"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await analyzer.analyze(
            domain="example.test",
            allow_private_in_testing=True,
        )

        assert result.mmh3_hash is None
        assert result.error is not None
        assert "exceeded max size" in result.error


@pytest.mark.asyncio
async def test_favicon_analyzer_ssrf_blocked():
    """Verify analyzer blocks requests targeting internal or cloud metadata IPs."""
    analyzer = FaviconAnalyzer()

    # Querying 169.254.169.254 without allow_private_in_testing
    result = await analyzer.analyze(
        domain="169.254.169.254",
        allow_private_in_testing=False,
    )

    assert result.mmh3_hash is None
    assert result.error is not None
    assert "SSRF validation blocked" in result.error


@pytest.mark.asyncio
async def test_favicon_analyzer_not_found():
    """Verify analyzer gracefully handles 404 / connection failures."""
    analyzer = FaviconAnalyzer()

    mock_resp = httpx.Response(
        404,
        request=httpx.Request("GET", "https://example.test/favicon.ico"),
    )

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await analyzer.analyze(
            domain="example.test",
            allow_private_in_testing=True,
        )

        assert result.mmh3_hash is None
        assert result.error is not None
