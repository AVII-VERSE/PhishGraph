"""URLhaus Threat Intelligence Provider (abuse.ch)."""

from typing import Optional
import httpx
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.urlhaus")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(ThreatIntelProvider):
    """URLhaus API Provider (Community Threat Intelligence)."""

    def __init__(
        self,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "urlhaus"

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.post(f"{URLHAUS_API}/url/", data={"url": url})
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json()
            query_status = data.get("query_status")

            if query_status == "no_results":
                return ThreatIntelResult(provider=self.name, status="not_found")
            elif query_status == "ok":
                threat = data.get("threat")
                tags = data.get("tags") or []
                url_status = data.get("url_status", "unknown")

                labels = [f"threat: {threat}"] if threat else []
                labels.extend(tags)

                return ThreatIntelResult(
                    provider=self.name,
                    status="success",
                    malicious=True,
                    suspicious=True,
                    score=90 if url_status == "online" else 75,
                    labels=labels,
                    raw_reference=str(data.get("id")),
                    details={"threat": threat, "status": url_status, "reporter": data.get("reporter")},
                )

            return ThreatIntelResult(provider=self.name, status="not_found")
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status="timeout")
        except Exception as exc:
            logger.debug(f"URLhaus lookup error: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.post(f"{URLHAUS_API}/host/", data={"host": domain})
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json()
            if data.get("query_status") == "ok":
                urls_count = len(data.get("urls", []))
                is_mal = urls_count > 0
                return ThreatIntelResult(
                    provider=self.name,
                    status="success",
                    malicious=is_mal,
                    suspicious=is_mal,
                    score=min(100, urls_count * 20),
                    labels=[f"known_malicious_urls: {urls_count}"],
                    raw_reference=domain,
                    details={"active_urls": urls_count},
                )
            return ThreatIntelResult(provider=self.name, status="not_found")
        except Exception as exc:
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        return await self.lookup_domain(ip)
