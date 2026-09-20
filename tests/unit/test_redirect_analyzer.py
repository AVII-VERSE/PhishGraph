"""Unit tests for Safe Redirect Analyzer."""

from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.analyzers.redirect_analyzer import trace_redirect_chain


@pytest.mark.asyncio
async def test_trace_redirect_chain_success():
    """Verify following standard HTTP redirect hops."""
    mock_client = MagicMock(spec=httpx.AsyncClient)

    # Hop 1: 301 from short.example/123 to tracker.example/click
    resp1 = MagicMock(spec=httpx.Response)
    resp1.status_code = 301
    resp1.is_redirect = True
    resp1.headers = {"Location": "https://tracker.example/click"}

    # Hop 2: 302 from tracker.example/click to target.example/login
    resp2 = MagicMock(spec=httpx.Response)
    resp2.status_code = 302
    resp2.is_redirect = True
    resp2.headers = {"Location": "https://target.example/login"}

    # Hop 3: 200 at destination
    resp3 = MagicMock(spec=httpx.Response)
    resp3.status_code = 200
    resp3.is_redirect = False

    mock_client.head = AsyncMock(side_effect=[resp1, resp2, resp3])

    # Allow private false, but mock validate_url_safety to return safe
    res = await trace_redirect_chain(
        "https://short.example/123",
        http_client=mock_client,
        allow_private_in_testing=True,
    )

    assert res.total_hops == 2
    assert res.final_url == "https://target.example/login"
    assert res.cross_domain_redirects == 2
    assert any("Multiple cross-domain" in s for s in res.signals)


@pytest.mark.asyncio
async def test_redirect_blocked_by_ssrf():
    """Verify that a redirect attempting to pivot to private IP is immediately aborted."""
    mock_client = MagicMock(spec=httpx.AsyncClient)

    # Initial URL redirects to a loopback/internal target
    resp1 = MagicMock(spec=httpx.Response)
    resp1.status_code = 302
    resp1.is_redirect = True
    resp1.headers = {"Location": "http://127.0.0.1/admin"}

    mock_client.head = AsyncMock(return_value=resp1)

    # We do NOT allow private here so SSRF guard halts the trace
    res = await trace_redirect_chain(
        "https://public-bounce.example/go",
        http_client=mock_client,
        allow_private_in_testing=False,
    )

    # Should be blocked at hop 2
    assert res.blocked_by_ssrf is True
    assert any("Redirect halted" in s for s in res.signals)
