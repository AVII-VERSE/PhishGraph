"""AlienVault OTX Threat Intelligence Provider."""

from typing import Optional
from urllib.parse import quote
import httpx
from app.config import get_settings
from app.logging import get_logger
from app.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = get_logger("phishgraph.threat_intel.otx")

OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators"


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault Open Threat Exchange (OTX) Provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 4.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key or get_settings().OTX_API_KEY
        self._timeout = timeout
        self._client = http_client

    @property
    def name(self) -> str:
        return "alienvault_otx"

    def _get_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key
        return headers

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        encoded_url = quote(url, safe="")
        endpoint = f"{OTX_API_BASE}/url/{encoded_url}/general"

        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code == 404:
                return ThreatIntelResult(provider=self.name, status="not_found")
            elif resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="error")

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulses_count = pulse_info.get("count", 0)

            labels: list[str] = []
            for p in pulse_info.get("pulses", [])[:3]:
                if p.get("name"):
                    labels.append(p["name"])

            is_mal = pulses_count >= 2
            is_susp = pulses_count == 1
            score = min(100, pulses_count * 25)

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=is_mal,
                suspicious=is_susp,
                score=score,
                labels=labels,
                details={"pulses_count": pulses_count},
            )
        except Exception as exc:
            logger.debug(f"OTX url error: {exc}")
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        endpoint = f"{OTX_API_BASE}/domain/{domain}/general"
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="not_found")

            pulse_info = resp.json().get("pulse_info", {})
            pulses = pulse_info.get("count", 0)

            labels: list[str] = []
            for p in pulse_info.get("pulses", [])[:3]:
                if p.get("name"):
                    labels.append(p["name"])

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=pulses >= 3,
                suspicious=pulses in (1, 2),
                score=min(100, pulses * 20),
                labels=labels,
                raw_reference=domain,
                details={"pulses_count": pulses},
            )
        except Exception as exc:
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(provider=self.name, status="skipped_no_key")

        endpoint = f"{OTX_API_BASE}/IPv4/{ip}/general"
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        try:
            resp = await client.get(endpoint, headers=self._get_headers())
            if resp.status_code != 200:
                return ThreatIntelResult(provider=self.name, status="not_found")

            pulse_info = resp.json().get("pulse_info", {})
            pulses = pulse_info.get("count", 0)

            labels: list[str] = []
            for p in pulse_info.get("pulses", [])[:3]:
                if p.get("name"):
                    labels.append(p["name"])

            return ThreatIntelResult(
                provider=self.name,
                status="success",
                malicious=pulses >= 3,
                suspicious=pulses in (1, 2),
                score=min(100, pulses * 20),
                labels=labels,
                raw_reference=ip,
                details={"pulses_count": pulses},
            )
        except Exception as exc:
            return ThreatIntelResult(provider=self.name, status="error", details={"error": str(exc)})
        finally:
            if self._client is None:
                await client.aclose()
