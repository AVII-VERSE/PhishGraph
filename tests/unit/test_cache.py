"""Unit tests for cache service."""

import asyncio
import pytest
from app.cache import CacheService, InMemoryCache


@pytest.mark.asyncio
async def test_in_memory_cache_basic_ops():
    """Verify basic key-value operations on InMemoryCache."""
    cache = InMemoryCache()

    assert await cache.get("test_key") is None
    assert await cache.set("test_key", "sample_value") is True
    assert await cache.get("test_key") == "sample_value"
    assert await cache.exists("test_key") is True

    assert await cache.delete("test_key") is True
    assert await cache.get("test_key") is None
    assert await cache.exists("test_key") is False


@pytest.mark.asyncio
async def test_in_memory_cache_ttl():
    """Verify TTL expiry on InMemoryCache."""
    cache = InMemoryCache()
    await cache.set("expiring_key", "temp_val", expire_seconds=1)

    assert await cache.get("expiring_key") == "temp_val"
    await asyncio.sleep(1.1)
    assert await cache.get("expiring_key") is None


@pytest.mark.asyncio
async def test_cache_service_fallback():
    """Verify CacheService operates properly with in-memory fallback."""
    service = CacheService()
    await service.initialize()

    assert service.backend_type in ("memory", "redis")
    assert await service.ping() is True

    await service.set("phishgraph:dns:example.com", '{"ip": "93.184.216.34"}', expire_seconds=60)
    cached_val = await service.get("phishgraph:dns:example.com")
    assert cached_val == '{"ip": "93.184.216.34"}'

    await service.delete("phishgraph:dns:example.com")
    assert await service.get("phishgraph:dns:example.com") is None
    await service.close()
