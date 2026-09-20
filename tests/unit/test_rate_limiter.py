"""Unit tests for sliding window rate limiter service (Section 39)."""

import pytest
import time
from app.services.rate_limiter import RateLimiter, get_rate_limiter


@pytest.mark.asyncio
async def test_rate_limiter_in_memory_sliding_window():
    """Verify in-memory sliding window enforces threshold."""
    limiter = RateLimiter()
    key = "test:user:123"

    # Allow up to 3 requests in 10 seconds
    for _ in range(3):
        is_limited, retry_after = await limiter.is_rate_limited(key=key, limit=3, window_seconds=10)
        assert is_limited is False
        assert retry_after == 0

    # 4th request should be blocked
    is_limited, retry_after = await limiter.is_rate_limited(key=key, limit=3, window_seconds=10)
    assert is_limited is True
    assert retry_after > 0
    assert retry_after <= 10


@pytest.mark.asyncio
async def test_rate_limiter_reset():
    """Verify reset_memory clears tracked history."""
    limiter = RateLimiter()
    key = "test:user:999"

    for _ in range(2):
        await limiter.is_rate_limited(key=key, limit=2, window_seconds=60)

    # Reached limit
    is_limited, _ = await limiter.is_rate_limited(key=key, limit=2, window_seconds=60)
    assert is_limited is True

    # Reset
    limiter.reset_memory()
    is_limited, _ = await limiter.is_rate_limited(key=key, limit=2, window_seconds=60)
    assert is_limited is False


@pytest.mark.asyncio
async def test_scan_rate_limiter_helper():
    """Verify check_scan_rate_limit helper function."""
    limiter = get_rate_limiter()
    limiter.reset_memory()

    is_limited, retry_after = await limiter.check_scan_rate_limit("tg_user_42")
    assert is_limited is False
    assert retry_after == 0
