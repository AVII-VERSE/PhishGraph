"""ThreatFox Threat Intelligence Provider (abuse.ch).

Queries community Indicators of Compromise (IOCs) including botnet C2s,
malware payloads, and phishing infrastructure.
No API key required for community lookups.
"""

from typing import Optional
import httpx
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.threatfox")

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(ThreatIntelProvider):
    """ThreatFox API v1 Provider (abuse.ch IOC database)."""

    def __init__(
        self,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "threatfox"

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            payload = {"query": "search_ioc", "search_term": url}
            resp = await client.post(THREATFOX_API, json=payload)
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json()
            query_status = data.get("query_status")

            if query_status == "no_result":
                return ThreatIntelResult(provider=self.name, status="not_found")
            elif query_status == "ok":
                ioc_list = data.get("data", [])
                if not ioc_list:
                    return ThreatIntelResult(provider=self.name, status="not_found")

                primary_match = ioc_list[0]
                malware_printable = primary_match.get("threat_type_desc") or primary_match.get("malware_printable")
                confidence_level = primary_match.get("confidence_level", 50)
                tags = primary_match.get("tags") or []

                labels = [f"threat: {malware_printable}"] if malware_printable else []
                labels.extend(tags)

                return ThreatIntelResult(
                    provider=self.name,
                    status="success",
                    malicious=True,
                    suspicious=True,
                    score=confidence_level,
                    labels=labels,
                    raw_reference=str(primary_match.get("id")),
                    details={
                        "threat_type": primary_match.get("threat_type"),
                        "malware": primary_match.get("malware"),
                        "reporter": primary_match.get("reporter"),
                    },
                )

            return ThreatIntelResult(provider=self.name, status="not_found")
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status="timeout")
        except Exception as exc:
            logger.debug(f"ThreatFox lookup failed for {url}: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if not self._client and not client.is_closed:
                await client.aclose()

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return await self.lookup_url(domain)

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        return await self.lookup_url(ip)
