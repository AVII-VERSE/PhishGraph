"""Unit tests for Threat Intelligence Aggregator."""

from unittest.mock import AsyncMock, MagicMock
import pytest
from app.threat_intel.aggregator import ThreatIntelAggregator
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult


class MockProvider(ThreatIntelProvider):

    def __init__(self, name: str, is_malicious: bool = False):
        self._name = name
        self._malicious = is_malicious
        self.call_count = 0

    @property
    def name(self) -> str:
        return self._name

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        self.call_count += 1
        return ThreatIntelResult(
            provider=self._name,
            status="success",
            malicious=self._malicious,
            score=80 if self._malicious else 0,
            labels=["test_label"] if self._malicious else [],
        )

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return await self.lookup_url(f"http://{domain}")

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        return await self.lookup_url(f"http://{ip}")


@pytest.mark.asyncio
async def test_aggregator_parallel_queries():
    """Verify aggregator dispatches to all providers in parallel."""
    p1 = MockProvider("prov1", is_malicious=False)
    p2 = MockProvider("prov2", is_malicious=True)

    aggregator = ThreatIntelAggregator(providers=[p1, p2])
    results = await aggregator.query_all(
        url="https://sample-test-url.example/path",
        domain="sample-test-url.example",
    )

    assert len(results) == 2
    assert p1.call_count == 1
    assert p2.call_count == 1

    positive_results = [r for r in results if r.is_positive]
    assert len(positive_results) == 1
    assert positive_results[0].provider == "prov2"


@pytest.mark.asyncio
async def test_aggregator_caching():
    """Verify results are cached and reused on subsequent lookups."""
    p1 = MockProvider("prov_cache_test", is_malicious=True)
    aggregator = ThreatIntelAggregator(providers=[p1])

    target = "https://unique-cache-target.test/login"

    # Call 1
    res1 = await aggregator.query_all(url=target, domain="unique-cache-target.test")
    assert p1.call_count == 1
    assert res1[0].malicious is True

    # Call 2: should retrieve from cache, so call_count on provider does not increment
    res2 = await aggregator.query_all(url=target, domain="unique-cache-target.test")
    assert p1.call_count == 1
    assert res2[0].malicious is True
