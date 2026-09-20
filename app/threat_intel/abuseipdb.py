"""AbuseIPDB IP Reputation Threat Intelligence Provider."""

from typing import Optional
import httpx
from app.config import get_settings
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.abuseipdb")

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API v2 Provider for Public IP reputation."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key or get_settings().ABUSEIPDB_API_KEY
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "abuseipdb"

    def _get_headers(self) -> dict[str, str]:
        return {
            "Key": self._api_key or "",
            "Accept": "application/json",
        }

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        # AbuseIPDB only inspects IP addresses directly
        return ThreatIntelResult(provider=self.name, status="not_supported")

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return ThreatIntelResult(provider=self.name, status="not_supported")

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(
                ABUSEIPDB_CHECK_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
                headers=self._get_headers(),
            )
            if resp.status_code == 429:
                return ThreatIntelResult(provider=self.name, status="rate_limited")
            elif resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            usage_type = data.get("usageType")
            isp = data.get("isp")

            is_mal = abuse_score >= 50
            is_susp = abuse_score >= 20

            labels: list[str] = []
            if abuse_score > 0:
                labels.append(f"abuse_confidence: {abuse_score}%")
            if total_reports > 0:
                labels.append(f"reports: {total_reports}")
            if usage_type:
                labels.append(f"type: {usage_type}")

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=is_mal,
                suspicious=is_susp,
                score=abuse_score,
                labels=labels,
                raw_reference=ip,
                details={
                    "abuse_confidence_score": abuse_score,
                    "total_reports": total_reports,
                    "isp": isp,
                    "country": data.get("countryCode"),
                },
            )
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status="timeout")
        except Exception as exc:
            logger.debug(f"AbuseIPDB lookup error for {ip}: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()
