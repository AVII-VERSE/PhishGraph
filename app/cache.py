"""Asynchronous caching layer with Redis backend and in-memory fallback."""

import asyncio
import time
from typing import Any, Optional
from app.config import get_settings
from app.logging import get_logger

logger = get_logger("phishgraph.cache")


class InMemoryCache:
    """Thread-safe in-memory cache with TTL support for local dev and tests."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, Optional[float]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            if key not in self._store:
                return None
            val, expiry = self._store[key]
            if expiry is not None and time.time() > expiry:
                del self._store[key]
                return None
            return val

    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        async with self._lock:
            expiry = (time.time() + expire_seconds) if expire_seconds else None
            self._store[key] = (str(value), expiry)
            return True

    async def delete(self, key: str) -> bool:
        async with self._lock:
            return self._store.pop(key, None) is not None

    async def exists(self, key: str) -> bool:
        val = await self.get(key)
        return val is not None

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        async with self._lock:
            self._store.clear()


class CacheService:
    """Unified cache service delegating to Redis or In-Memory fallback."""

    def __init__(self) -> None:
        self._redis: Optional[Any] = None
        self._memory_cache = InMemoryCache()
        self._backend: str = "memory"

    async def initialize(self) -> None:
        settings = get_settings()
        if settings.REDIS_URL:
            try:
                import redis.asyncio as aioredis

                client = aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=2.0,
                )
                await client.ping()
                self._redis = client
                self._backend = "redis"
                logger.info("Connected to Redis cache successfully")
                return
            except Exception as exc:
                logger.warning(f"Could not connect to Redis at {settings.REDIS_URL}: {exc}. Using in-memory fallback.")

        self._redis = None
        self._backend = "memory"
        logger.info("Using in-memory cache backend")

    @property
    def backend_type(self) -> str:
        return self._backend

    async def get(self, key: str) -> Optional[str]:
        if self._redis:
            try:
                return await self._redis.get(key)
            except Exception as exc:
                logger.warning(f"Redis get failed for {key}: {exc}")
        return await self._memory_cache.get(key)

    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.set(key, value, ex=expire_seconds))
            except Exception as exc:
                logger.warning(f"Redis set failed for {key}: {exc}")
        return await self._memory_cache.set(key, value, expire_seconds)

    async def delete(self, key: str) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.delete(key))
            except Exception as exc:
                logger.warning(f"Redis delete failed for {key}: {exc}")
        return await self._memory_cache.delete(key)

    async def exists(self, key: str) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.exists(key))
            except Exception as exc:
                logger.warning(f"Redis exists failed for {key}: {exc}")
        return await self._memory_cache.exists(key)

    async def ping(self) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.ping())
            except Exception:
                return False
        return await self._memory_cache.ping()

    async def close(self) -> None:
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception as exc:
                logger.warning(f"Error closing Redis connection: {exc}")
            self._redis = None
        await self._memory_cache.close()


_cache_instance: Optional[CacheService] = None


async def get_cache() -> CacheService:
    """Get or initialize global cache service singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = CacheService()
        await _cache_instance.initialize()
    return _cache_instance
