"""Rate limiting and abuse prevention service adhering to Section 39."""

import time
from collections import defaultdict, deque
from typing import Optional, Tuple
from app.cache import get_cache
from app.config import get_settings
from app.logging import get_logger

logger = get_logger("phishgraph.rate_limiter")


class RateLimiter:
    """Sliding-window rate limiter with Redis backend and in-memory fallback."""

    def __init__(self) -> None:
        self._memory_buckets: dict[str, deque[float]] = defaultdict(deque)

    async def is_rate_limited(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """
        Check if a given key exceeds limit in window_seconds using sliding window.

        Returns:
            (is_limited, retry_after_seconds)
        """
        now = time.time()

        # Try redis sliding window via sorted set if available
        try:
            cache = await get_cache()
            if cache.backend_type == "redis" and cache.redis:
                redis_client = cache.redis
                rkey = f"phishgraph:ratelimit:{key}"
                pipe = redis_client.pipeline()
                pipe.zremrangebyscore(rkey, 0, now - window_seconds)
                pipe.zadd(rkey, {str(now): now})
                pipe.zcard(rkey)
                pipe.expire(rkey, window_seconds + 5)
                results = await pipe.execute()
                current_count = results[2]

                if current_count > limit:
                    oldest_res = await redis_client.zrange(rkey, 0, 0, withscores=True)
                    if oldest_res:
                        oldest_ts = oldest_res[0][1]
                        retry_after = max(1, int(window_seconds - (now - oldest_ts)))
                    else:
                        retry_after = window_seconds
                    return True, retry_after
                return False, 0
        except Exception as e:
            logger.debug("Redis rate limiting failed, falling back to memory: %s", e)

        # In-memory sliding window queue
        dq = self._memory_buckets[key]
        cutoff = now - window_seconds
        while dq and dq[0] <= cutoff:
            dq.popleft()

        if len(dq) >= limit:
            oldest = dq[0]
            retry_after = max(1, int(window_seconds - (now - oldest)))
            return True, retry_after

        dq.append(now)
        return False, 0

    async def check_scan_rate_limit(self, user_id: int | str) -> Tuple[bool, int]:
        """Check Telegram user scan rate limit (10 scans / 10 min by default)."""
        settings = get_settings()
        key = f"scan:user:{user_id}"
        return await self.is_rate_limited(
            key=key,
            limit=settings.RATE_LIMIT_SCANS_PER_WINDOW,
            window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
        )

    async def check_api_rate_limit(self, client_ip: str) -> Tuple[bool, int]:
        """Check API client rate limit (60 requests / minute)."""
        key = f"api:ip:{client_ip}"
        return await self.is_rate_limited(
            key=key,
            limit=60,
            window_seconds=60,
        )

    def reset_memory(self) -> None:
        """Reset internal in-memory buckets (primarily for testing)."""
        self._memory_buckets.clear()


_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Singleton getter for RateLimiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
