"""VirusTotal Threat Intelligence Provider."""

import base64
from typing import Optional
import httpx
from app.config import get_settings
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.virustotal")

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 Provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key or get_settings().VIRUSTOTAL_API_KEY
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "virustotal"

    def _get_headers(self) -> dict[str, str]:
        return {
            "x-apikey": self._api_key or "",
            "Accept": "application/json",
        }

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        # Encode URL according to VirusTotal v3 specification
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{VT_API_BASE}/urls/{url_id}"

        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code == 404:
                return ThreatIntelResult(provider=self.name, status="not_found")
            elif resp.status_code == 429:
                return ThreatIntelResult(provider=self.name, status="rate_limited")
            elif resp.status_code != 200:
                return ThreatIntelResult(
                    provider=self.name,
                    status="error",
                    details={"http_status": resp.status_code},
                )

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            labels: list[str] = []
            categories = data.get("categories", {})
            for eng, cat in categories.items():
                if cat in ("phishing", "malicious"):
                    labels.append(f"{cat} ({eng})")

            is_mal = malicious_count >= 1
            is_susp = suspicious_count >= 1

            # Normalize detection count into 0-100 score
            score = min(100, (malicious_count * 20) + (suspicious_count * 10))

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=is_mal,
                suspicious=is_susp,
                score=score,
                labels=labels[:5],
                raw_reference=url_id,
                details={"malicious_engines": malicious_count, "suspicious_engines": suspicious_count},
            )
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status="timeout")
        except Exception as exc:
            logger.debug(f"VirusTotal lookup error: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        endpoint = f"{VT_API_BASE}/domains/{domain}"
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code == 404:
                return ThreatIntelResult(provider=self.name, status="not_found")
            elif resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=malicious_count >= 2,
                suspicious=malicious_count == 1,
                score=min(100, malicious_count * 15),
                raw_reference=domain,
                details=stats,
            )
        except Exception as exc:
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        endpoint = f"{VT_API_BASE}/ip_addresses/{ip}"
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="not_found")

            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=malicious_count >= 3,
                suspicious=malicious_count in (1, 2),
                score=min(100, malicious_count * 15),
                raw_reference=ip,
                details=stats,
            )
        except Exception as exc:
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()
