"""Google Safe Browsing v4 Threat Intelligence Provider."""

from typing import Optional
import httpx
from app.config import get_settings
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.safebrowsing")

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """Google Safe Browsing Lookup API v4 Provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key or get_settings().GOOGLE_SAFE_BROWSING_API_KEY
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "google_safebrowsing"

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        payload = {
            "client": {"clientId": "phishgraph", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.post(
                f"{GSB_API_URL}?key={self._api_key}",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 400:
                return ThreatIntelResult(provider=self.name, status="error", details={"reason": "Invalid key or payload"})
            elif resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            matches = resp.json().get("matches", [])
            if not matches:
                return ThreatIntelResult(provider=self.name, status="not_found")

            labels = [m.get("threatType", "THREAT") for m in matches]
            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=True,
                suspicious=True,
                score=95,
                labels=labels,
                details={"matches_count": len(matches)},
            )
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status="timeout")
        except Exception as exc:
            logger.debug(f"Google Safe Browsing lookup error: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return await self.lookup_url(f"http://{domain}/")

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        return await self.lookup_url(f"http://{ip}/")
