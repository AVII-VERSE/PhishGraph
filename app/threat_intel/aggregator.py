"""Threat Intelligence Aggregator orchestrating multi-provider queries."""

import asyncio
import hashlib
from typing import List, Optional
from app.cache import get_cache
from app.logging import get_logger
from app.threat_intel.abuseipdb import AbuseIPDBProvider
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from app.threat_intel.otx import AlienVaultOTXProvider
from app.threat_intel.safebrowsing import GoogleSafeBrowsingProvider
from app.threat_intel.urlhaus import URLhausProvider
from app.threat_intel.virustotal import VirusTotalProvider

logger = get_logger("phishgraph.threat_intel.aggregator")


class ThreatIntelAggregator:
    """Orchestrates parallel threat intelligence lookups with caching."""

    def __init__(self, providers: Optional[List[ThreatIntelProvider]] = None):
        self.providers = providers or [
            VirusTotalProvider(),
            URLhausProvider(),
            AlienVaultOTXProvider(),
            GoogleSafeBrowsingProvider(),
            AbuseIPDBProvider(),
        ]

    async def _query_with_cache(
        self,
        provider: ThreatIntelProvider,
        query_type: str,
        indicator: str,
        coro,
    ) -> ThreatIntelResult:
        """Wrap individual provider lookup with cache check and fallback."""
        cache = await get_cache()
        indicator_hash = hashlib.sha256(indicator.lower().encode()).hexdigest()[:16]
        cache_key = f"phishgraph:ti:{provider.name}:{query_type}:{indicator_hash}"

        # 1. Check cache
        cached = await cache.get(cache_key)
        if cached:
            if hasattr(coro, "close"):
                coro.close()
            try:
                return ThreatIntelResult.model_validate_json(cached)
            except Exception:
                pass

        # 2. Execute query
        try:
            result = await coro
        except asyncio.TimeoutError:
            result = ThreatIntelResult(provider=provider.name, status="timeout")
        except Exception as exc:
            logger.debug(f"Provider {provider.name} failed on {indicator}: {exc}")
            result = ThreatIntelResult(provider=provider.name, status="error", details={"error": str(exc)})

        # 3. Cache positive / successful results (2 hours)
        if result.status == "success":
            try:
                await cache.set(cache_key, result.model_dump_json(), expire_seconds=7200)
            except Exception:
                pass

        return result

    async def query_all(
        self,
        url: str,
        domain: str,
        resolved_ips: Optional[List[str]] = None,
    ) -> List[ThreatIntelResult]:
        """
        Query all registered threat-intelligence providers in parallel.
        Dispatches URL, domain, and IP queries where applicable.
        """
        ips = resolved_ips or []
        tasks = []

        for provider in self.providers:
            if provider.name == "abuseipdb":
                # AbuseIPDB inspects public resolved IPs
                for ip in ips[:2]:  # Query at most top 2 resolved IPs
                    tasks.append(
                        self._query_with_cache(
                            provider, "ip", ip, provider.lookup_ip(ip)
                        )
                    )
            else:
                # URL reputation
                tasks.append(
                    self._query_with_cache(
                        provider, "url", url, provider.lookup_url(url)
                    )
                )

        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)
