"""Campaign Correlation Engine.

Compares infrastructure fingerprints against historical scan records
to detect infrastructure reuse and potential campaign clusters.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Set
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.fingerprint import FingerprintData
from app.db.models.correlation import Correlation
from app.db.models.fingerprint import Fingerprint

logger = logging.getLogger(__name__)

# Initial relationship weights from README Section 13
WEIGHT_SAME_FAVICON_HASH = 25
WEIGHT_SAME_TLS_SERIAL = 25
WEIGHT_SAME_REDIRECT_TARGET = 20
WEIGHT_SAME_NAMESERVER = 15
WEIGHT_SAME_GENERIC_NAMESERVER = 5
WEIGHT_SAME_IP = 10
WEIGHT_SAME_ASN = 5
WEIGHT_SAME_REGISTRAR = 3
WEIGHT_SAME_BRAND_TARGET = 5

# Common multi-tenant nameserver substrings
GENERIC_NAMESERVERS = {
    "cloudflare.com",
    "awsdns",
    "domaincontrol.com",
    "registrar-servers.com",
    "googledomains.com",
    "dns-parking.com",
    "name-services.com",
}


@dataclass
class CorrelationMatch:
    """Individual correlated domain and relationship evidence."""

    related_domain: str
    related_scan_id: int
    score: int
    relations: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Aggregated correlation result for a scan."""

    scan_id: int
    domain: str
    matches: List[CorrelationMatch] = field(default_factory=list)

    @property
    def total_matches(self) -> int:
        return len(self.matches)


class CorrelationEngine:
    """Evaluates infrastructure relationships between new and historical scans."""

    def __init__(self, min_score_threshold: int = 15) -> None:
        self.min_score_threshold = min_score_threshold

    def compare_fingerprints(
        self,
        current: FingerprintData,
        historical: FingerprintData,
    ) -> Optional[CorrelationMatch]:
        """Compare current fingerprint with a historical fingerprint."""
        # Skip identical domain
        if current.domain.lower() == historical.domain.lower():
            return None

        score = 0
        relations: List[str] = []

        # 1. Favicon Hash
        if (
            current.favicon_hash
            and historical.favicon_hash
            and current.favicon_hash == historical.favicon_hash
        ):
            score += WEIGHT_SAME_FAVICON_HASH
            relations.append("SAME_FAVICON_HASH")

        # 2. TLS Serial
        if (
            current.tls_serial
            and historical.tls_serial
            and current.tls_serial == historical.tls_serial
        ):
            score += WEIGHT_SAME_TLS_SERIAL
            relations.append("SAME_TLS_SERIAL")

        # 3. Redirect Destinations
        current_redirects = set(current.redirect_domain_set)
        hist_redirects = set(historical.redirect_domain_set)
        shared_redirects = current_redirects.intersection(hist_redirects)
        if shared_redirects:
            score += WEIGHT_SAME_REDIRECT_TARGET
            relations.append("SAME_REDIRECT_TARGET")

        # 4. Nameservers
        current_ns = {ns.lower() for ns in current.nameserver_set}
        hist_ns = {ns.lower() for ns in historical.nameserver_set}
        shared_ns = current_ns.intersection(hist_ns)
        if shared_ns:
            is_generic = any(
                any(g in ns for g in GENERIC_NAMESERVERS)
                for ns in shared_ns
            )
            if is_generic:
                score += WEIGHT_SAME_GENERIC_NAMESERVER
            else:
                score += WEIGHT_SAME_NAMESERVER
            relations.append("SAME_NAMESERVER")

        # 5. IP Addresses
        current_ips = set(current.ip_set)
        hist_ips = set(historical.ip_set)
        shared_ips = current_ips.intersection(hist_ips)
        if shared_ips:
            score += WEIGHT_SAME_IP
            relations.append("SAME_IP")

        # 6. ASN (only if IPs not completely identical or as supporting signal)
        if (
            current.asn
            and historical.asn
            and current.asn.upper() == historical.asn.upper()
        ):
            score += WEIGHT_SAME_ASN
            relations.append("SAME_ASN")

        # 7. Registrar
        if (
            current.registrar
            and historical.registrar
            and current.registrar.strip().lower() == historical.registrar.strip().lower()
        ):
            score += WEIGHT_SAME_REGISTRAR
            relations.append("SAME_REGISTRAR")

        # 8. Brand Target
        if (
            current.brand_target
            and historical.brand_target
            and current.brand_target.lower() == historical.brand_target.lower()
        ):
            score += WEIGHT_SAME_BRAND_TARGET
            relations.append("SAME_BRAND_TARGET")

        # Cap at 100
        score = min(score, 100)

        if score >= self.min_score_threshold:
            return CorrelationMatch(
                related_domain=historical.domain,
                related_scan_id=historical.scan_id,
                score=score,
                relations=relations,
            )

        return None

    async def correlate(
        self,
        current: FingerprintData,
        session: AsyncSession,
        persist: bool = True,
    ) -> CorrelationResult:
        """Query historical fingerprints, calculate correlation, and optionally persist."""
        stmt = (
            select(Fingerprint)
            .where(Fingerprint.scan_id != current.scan_id)
            .order_by(Fingerprint.id.desc())
            .limit(200)
        )
        result = await session.execute(stmt)
        records = result.scalars().all()

        matches: List[CorrelationMatch] = []
        seen_domains: Set[str] = set()

        for rec in records:
            if rec.domain.lower() in seen_domains:
                continue

            hist_data = FingerprintData(
                scan_id=rec.scan_id,
                domain=rec.domain,
                ip_set=rec.ip_set or [],
                asn=rec.asn,
                nameserver_set=rec.nameserver_set or [],
                registrar=rec.registrar,
                tls_serial=rec.tls_serial,
                tls_issuer=rec.tls_issuer,
                favicon_hash=rec.favicon_hash,
                page_hash=rec.page_hash,
                redirect_domain_set=rec.redirect_domain_set or [],
                brand_target=None,
            )

            match = self.compare_fingerprints(current, hist_data)
            if match:
                matches.append(match)
                seen_domains.add(match.related_domain.lower())

                if persist:
                    corr_record = Correlation(
                        source_scan_id=current.scan_id,
                        target_scan_id=match.related_scan_id,
                        correlation_score=match.score,
                        relationship_types=match.relations,
                    )
                    session.add(corr_record)

        if persist and matches:
            await session.flush()

        # Sort matches by score descending
        matches.sort(key=lambda m: m.score, reverse=True)

        return CorrelationResult(
            scan_id=current.scan_id,
            domain=current.domain,
            matches=matches,
        )
