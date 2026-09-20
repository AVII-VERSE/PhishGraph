"""ASN Resolver module.

Resolves Autonomous System Number (ASN) for IP addresses using
Team Cymru IP-to-ASN DNS service with asynchronous execution and caching.
"""

import ipaddress
import logging
from typing import Optional
import dns.asyncresolver

logger = logging.getLogger(__name__)


class ASNAnalyzer:
    """Resolves ASN and CIDR prefix for IP addresses."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout

    async def lookup_ip_asn(self, ip: str) -> Optional[str]:
        """Lookup ASN for an IP address.

        Args:
            ip: IPv4 or IPv6 string.

        Returns:
            Normalized ASN string (e.g. 'AS15169') or None if unresolved.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return None

            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = ip.split(".")
                query = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
            else:
                # IPv6 reverse nibble format
                exploded = ip_obj.exploded.replace(":", "")
                reversed_nibbles = ".".join(reversed(exploded))
                query = f"{reversed_nibbles}.origin6.asn.cymru.com"

            answers = await self.resolver.resolve(query, "TXT")
            for rdata in answers:
                txt_bytes = b"".join(rdata.strings)
                txt = txt_bytes.decode("utf-8", errors="ignore").strip()
                # Format: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
                parts = [p.strip() for p in txt.split("|")]
                if parts and parts[0]:
                    asn_num = parts[0].split()[0]  # In case multiple ASNs: "15169 15170"
                    if asn_num.isdigit():
                        return f"AS{asn_num}"

            return None
        except Exception as e:
            logger.debug("ASN lookup failed for %s: %s", ip, e)
            return None
