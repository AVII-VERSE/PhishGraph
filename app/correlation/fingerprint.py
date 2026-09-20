"""Fingerprint data structures and builder."""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.favicon_analyzer import FaviconResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult


@dataclass
class FingerprintData:
    """Normalized structured infrastructure fingerprint for a scan."""

    scan_id: int
    domain: str
    ip_set: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    nameserver_set: List[str] = field(default_factory=list)
    registrar: Optional[str] = None
    tls_serial: Optional[str] = None
    tls_issuer: Optional[str] = None
    favicon_hash: Optional[str] = None
    page_hash: Optional[str] = None
    redirect_domain_set: List[str] = field(default_factory=list)
    brand_target: Optional[str] = None


def build_fingerprint(
    scan_id: int,
    domain: str,
    dns_res: Optional[DNSAnalysisResult] = None,
    domain_info: Optional[DomainIntelligenceResult] = None,
    tls_res: Optional[TLSAnalysisResult] = None,
    redirect_res: Optional[RedirectChainResult] = None,
    favicon_res: Optional[FaviconResult] = None,
    asn: Optional[str] = None,
    brand_target: Optional[str] = None,
) -> FingerprintData:
    """Build a normalized FingerprintData from component analysis results."""
    # 1. IP set
    ips: set[str] = set()
    if dns_res:
        for r in dns_res.records:
            if r.record_type in ("A", "AAAA") and r.value:
                ips.add(r.value.strip())

    # 2. Nameserver set (clean trailing dot and lowercase)
    nameservers: set[str] = set()
    if dns_res:
        for r in dns_res.records:
            if r.record_type == "NS" and r.value:
                ns = r.value.strip().rstrip(".").lower()
                if ns:
                    nameservers.add(ns)

    # 3. Registrar
    registrar = domain_info.registrar if domain_info and domain_info.registrar else None

    # 4. TLS details
    tls_serial = tls_res.serial_number if tls_res and tls_res.serial_number else None
    tls_issuer = tls_res.issuer if tls_res and tls_res.issuer else None

    # 5. Favicon hash
    favicon_hash = None
    if favicon_res and favicon_res.mmh3_hash:
        favicon_hash = favicon_res.mmh3_hash
    elif favicon_res and favicon_res.sha256_hash:
        favicon_hash = favicon_res.sha256_hash

    # 6. Redirect domain set
    redirect_domains: set[str] = set()
    if redirect_res:
        for hop in redirect_res.hops:
            if hop.destination_url:
                try:
                    hop_domain = urlparse(hop.destination_url).netloc.split(":")[0].lower()
                    if hop_domain and hop_domain != domain.lower():
                        redirect_domains.add(hop_domain)
                except Exception:
                    pass

    return FingerprintData(
        scan_id=scan_id,
        domain=domain.lower().strip(),
        ip_set=sorted(list(ips)),
        asn=asn,
        nameserver_set=sorted(list(nameservers)),
        registrar=registrar,
        tls_serial=tls_serial,
        tls_issuer=tls_issuer,
        favicon_hash=favicon_hash,
        page_hash=None,
        redirect_domain_set=sorted(list(redirect_domains)),
        brand_target=brand_target,
    )
