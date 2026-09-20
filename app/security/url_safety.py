"""SSRF Protection and URL Safety Validation Engine."""

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse
import dns.asyncresolver
from app.logging import get_logger

logger = get_logger("phishgraph.security.ssrf")

# Forbidden hostnames (cloud metadata, container internal endpoints)
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.google.internal.",
    "instance-data",
    "169.254.169.254",
    "metadata.local",
    "kubernetes.default",
    "kubernetes.default.svc",
}


def is_ip_allowed(ip_str: str) -> bool:
    """
    Validate an IPv4 or IPv6 address against private and restricted ranges.
    Returns True if IP is public/routable, False if private/reserved/loopback/cloud metadata.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    # Explicit check for AWS/GCP/Azure link-local cloud metadata
    if ip_str == "169.254.169.254" or ip_str == "fd00:ec2::254":
        return False

    # Explicit check for carrier-grade NAT (100.64.0.0/10)
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    if ip in cgnat:
        return False

    return True


async def resolve_hostname_ips(hostname: str, timeout: float = 3.0) -> List[str]:
    """Resolve A and AAAA records asynchronously for SSRF address inspection."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    ips: List[str] = []

    # Query A records (IPv4)
    try:
        answers = await resolver.resolve(hostname, "A")
        for rdata in answers:
            ips.append(rdata.address)
    except Exception:
        pass

    # Query AAAA records (IPv6)
    try:
        answers = await resolver.resolve(hostname, "AAAA")
        for rdata in answers:
            ips.append(rdata.address)
    except Exception:
        pass

    # Fallback to getaddrinfo if dns.asyncresolver returned empty
    if not ips:
        try:
            addr_info = await asyncio_getaddrinfo(hostname)
            ips.extend(addr_info)
        except Exception:
            pass

    return list(dict.fromkeys(ips))


async def asyncio_getaddrinfo(hostname: str) -> List[str]:
    """Helper using standard socket getaddrinfo in async executor."""
    import asyncio

    loop = asyncio.get_running_loop()

    def _lookup() -> List[str]:
        results: List[str] = []
        try:
            for item in socket.getaddrinfo(hostname, None):
                sockaddr = item[4]
                if sockaddr and sockaddr[0]:
                    results.append(sockaddr[0])
        except Exception:
            pass
        return results

    return await loop.run_in_executor(None, _lookup)


async def validate_url_safety(
    url: str,
    allow_private_in_testing: bool = False,
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Validate target URL against SSRF threats:
    1. Scheme check (only http, https)
    2. Hostname format & cloud metadata names
    3. Direct IP inspection
    4. DNS resolution & resolved IP inspection

    Returns: (is_safe: bool, rejection_reason: Optional[str], resolved_ips: List[str])
    """
    if not url:
        return False, "URL is empty", []

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed URL: {exc}", []

    # Scheme verification
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http:// and https:// are permitted.", []

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in URL", []

    hostname_clean = hostname.lower().strip()

    # Block well-known cloud metadata hostnames
    if hostname_clean in BLOCKED_HOSTNAMES:
        return False, f"Access to restricted hostname '{hostname_clean}' is blocked.", []

    # Check if hostname is directly an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname_clean)
        if not allow_private_in_testing and not is_ip_allowed(str(ip_obj)):
            return False, f"Destination IP '{ip_obj}' is in a private or restricted network range.", [str(ip_obj)]
        return True, None, [str(ip_obj)]
    except ValueError:
        pass

    # Resolve hostname to inspect underlying destination addresses
    resolved_ips = await resolve_hostname_ips(hostname_clean)
    if not resolved_ips:
        if allow_private_in_testing:
            # Allow simulated/unresolvable test hostnames when explicitly configured in testing
            return True, None, ["127.0.0.1"]
        return False, f"Hostname '{hostname_clean}' could not be resolved to any IP address.", []

    if not allow_private_in_testing:
        for ip_addr in resolved_ips:
            if not is_ip_allowed(ip_addr):
                logger.warning(f"SSRF blocked: {hostname_clean} resolved to forbidden IP {ip_addr}")
                return False, f"Destination domain resolves to restricted network address ({ip_addr}).", resolved_ips

    return True, None, resolved_ips
