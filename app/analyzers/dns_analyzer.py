"""Asynchronous DNS analyzer querying standard resource records."""

import asyncio
from typing import Dict, List, Optional
import dns.asyncresolver
import dns.resolver
from pydantic import BaseModel, Field
from app.logging import get_logger

logger = get_logger("phishgraph.analyzers.dns")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


class DNSRecordItem(BaseModel):
    """Normalized DNS record item."""

    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None


class DNSAnalysisResult(BaseModel):
    """Aggregate result of DNS reconnaissance."""

    domain: str
    records: List[DNSRecordItem] = Field(default_factory=list)
    records_by_type: Dict[str, List[str]] = Field(default_factory=dict)
    resolved_ips: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    mx_hosts: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    has_a_record: bool = False
    has_mx_record: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    flag_emoji: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    city: Optional[str] = None


async def query_record_type(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
    rtype: str,
) -> List[DNSRecordItem]:
    """Query a specific DNS record type with async resolver."""
    items: List[DNSRecordItem] = []
    try:
        answers = await resolver.resolve(domain, rtype)
        ttl = answers.rrset.ttl if answers.rrset else None
        for rdata in answers:
            val = str(rdata).strip('"')
            items.append(DNSRecordItem(record_type=rtype, name=domain, value=val, ttl=ttl))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except Exception as exc:
        logger.debug(f"DNS {rtype} lookup for {domain} encountered: {exc}")
    return items


async def analyze_dns(
    domain: str,
    timeout: float = 3.0,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> DNSAnalysisResult:
    """Perform concurrent asynchronous DNS lookups across standard record types."""
    res = resolver or dns.asyncresolver.Resolver()
    res.timeout = timeout
    res.lifetime = timeout

    tasks = [query_record_type(res, domain, rtype) for rtype in RECORD_TYPES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_records: List[DNSRecordItem] = []
    by_type: Dict[str, List[str]] = {rtype: [] for rtype in RECORD_TYPES}
    ips: List[str] = []
    nameservers: List[str] = []
    mx_hosts: List[str] = []

    for res_group in results:
        if isinstance(res_group, list):
            for item in res_group:
                all_records.append(item)
                by_type[item.record_type].append(item.value)
                if item.record_type in ("A", "AAAA"):
                    ips.append(item.value)
                elif item.record_type == "NS":
                    nameservers.append(item.value.rstrip("."))
                elif item.record_type == "MX":
                    # MX value is usually "10 mail.example.com"
                    mx_parts = item.value.split()
                    host = mx_parts[-1].rstrip(".") if mx_parts else item.value
                    mx_hosts.append(host)

    signals: List[str] = []
    has_a = len(by_type.get("A", [])) > 0 or len(by_type.get("AAAA", [])) > 0
    has_mx = len(by_type.get("MX", [])) > 0

    if not has_a:
        signals.append("No A or AAAA address records found for domain")
    if not has_mx:
        signals.append("No MX (Mail Exchange) record configured")
    if len(nameservers) == 1:
        signals.append("Only a single nameserver observed")

    return DNSAnalysisResult(
        domain=domain,
        records=all_records,
        records_by_type=by_type,
        resolved_ips=sorted(list(set(ips))),
        nameservers=sorted(list(set(nameservers))),
        mx_hosts=sorted(list(set(mx_hosts))),
        signals=signals,
        has_a_record=has_a,
        has_mx_record=has_mx,
    )
