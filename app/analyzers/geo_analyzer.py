"""IP Geolocation and ASN organization analyzer with caching and SSRF validation."""

from dataclasses import dataclass
from typing import Optional
import httpx
from app.cache import get_cache
from app.logging import get_logger
from app.security.url_safety import is_ip_allowed

logger = get_logger("phishgraph.analyzers.geo")


def country_code_to_flag(country_code: str) -> str:
    """Convert 2-letter ISO country code to Unicode flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c.upper())) for c in country_code)


@dataclass
class GeoIPResult:
    """Structured IP geolocation intelligence."""

    ip: str
    country: str = "Unknown"
    country_code: str = ""
    flag_emoji: str = "🌐"
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""


class GeoIPAnalyzer:
    """Resolves IP addresses to geographical location and hosting provider."""

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        self.timeout = timeout_seconds

    async def lookup(self, ip: str) -> GeoIPResult:
        """Lookup geolocation metadata for a public IP."""
        if not ip or not is_ip_allowed(ip):
            return GeoIPResult(ip=ip, country="Private/Internal Network", flag_emoji="🔒")

        cache_key = f"phishgraph:geo:{ip}"
        try:
            cache = await get_cache()
            cached = await cache.get(cache_key)
            if cached and isinstance(cached, dict):
                return GeoIPResult(**cached)
        except Exception:
            pass

        # Query ip-api.com (free, high-speed, no API key required for non-commercial)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        cc = data.get("countryCode", "")
                        result = GeoIPResult(
                            ip=ip,
                            country=data.get("country", "Unknown"),
                            country_code=cc,
                            flag_emoji=country_code_to_flag(cc),
                            region=data.get("regionName", ""),
                            city=data.get("city", ""),
                            isp=data.get("isp", ""),
                            org=data.get("org", ""),
                            asn=data.get("as", ""),
                        )
                        # Cache for 24 hours
                        try:
                            cache = await get_cache()
                            await cache.set(cache_key, result.__dict__, ttl_seconds=86400)
                        except Exception:
                            pass
                        return result
        except Exception as exc:
            logger.debug(f"GeoIP query failed for {ip}: {exc}")

        return GeoIPResult(ip=ip, country="Unknown", flag_emoji="🌐")
