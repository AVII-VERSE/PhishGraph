"""Integration tests for rate limiting, quotas, and operational metrics (Section 39)."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.rate_limiter import get_rate_limiter
from app.services.scan_service import ScanService
from app.services.watch_service import WatchService


@pytest.mark.asyncio
async def test_get_metrics_json(async_client: AsyncClient):
    """Verify /metrics returns JSON summary by default."""
    res = await async_client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "uptime_seconds" in data
    assert "runtime" in data
    assert "database" in data
    assert "total_scans" in data["database"]


@pytest.mark.asyncio
async def test_get_metrics_prometheus(async_client: AsyncClient):
    """Verify /metrics with text/plain Accept header returns Prometheus format."""
    res = await async_client.get("/metrics", headers={"Accept": "text/plain"})
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    assert "phishgraph_uptime_seconds" in res.text
    assert "phishgraph_scans_total" in res.text


@pytest.mark.asyncio
async def test_api_rate_limiting_middleware(async_client: AsyncClient):
    """Verify API client rate limiter rejects excessive requests with 429."""
    limiter = get_rate_limiter()
    limiter.reset_memory()

    client_headers = {"x-forwarded-for": "198.51.100.99"}

    # Execute 60 allowed requests
    for _ in range(60):
        res = await async_client.get("/api/v1/scans/non-existent-scan", headers=client_headers)
        assert res.status_code == 404

    # 61st request should be throttled
    throttled = await async_client.get("/api/v1/scans/non-existent-scan", headers=client_headers)
    assert throttled.status_code == 429
    data = throttled.json()
    assert data["error"] == "Rate limit exceeded"
    assert "Retry-After" in throttled.headers

    # Whitelisted health endpoint should still succeed
    health_res = await async_client.get("/health", headers=client_headers)
    assert health_res.status_code == 200


@pytest.mark.asyncio
async def test_watchlist_quota_limit(db_session: AsyncSession):
    """Verify user cannot exceed maximum active watchlist entries (quota enforcement)."""
    user = await ScanService.get_or_create_user(
        session=db_session,
        telegram_user_id=888888,
        username="quota_tester",
    )

    # Add 10 allowed watches
    for i in range(10):
        await WatchService.add_watch(
            session=db_session,
            user_id=user.id,
            raw_url=f"https://quota-test-{i}.example.com",
            interval_hours=12,
        )

    # 11th addition should fail with ValueError
    with pytest.raises(ValueError, match="Watchlist quota exceeded"):
        await WatchService.add_watch(
            session=db_session,
            user_id=user.id,
            raw_url="https://quota-test-11.example.com",
            interval_hours=12,
        )
