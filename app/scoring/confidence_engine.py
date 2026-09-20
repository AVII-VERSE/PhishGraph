"""Independent Evidence Confidence Scoring Engine."""

from typing import List, Optional
from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.scoring.weights import (
    CONF_BASE,
    CONF_DNS_AVAILABLE,
    CONF_RDAP_AVAILABLE,
    CONF_REDIRECT_TRACED,
    CONF_TI_FEEDS_AGREEMENT,
    CONF_TLS_AVAILABLE,
)
from app.threat_intel.base import ThreatIntelResult


def calculate_confidence_score(
    dns_res: Optional[DNSAnalysisResult] = None,
    rdap_res: Optional[DomainIntelligenceResult] = None,
    tls_res: Optional[TLSAnalysisResult] = None,
    redir_res: Optional[RedirectChainResult] = None,
    ti_results: Optional[List[ThreatIntelResult]] = None,
) -> float:
    """
    Calculate 0–100 evidence confidence score measuring independent corroboration.
    Operates independently from the threat risk score.
    """
    confidence = float(CONF_BASE)

    # 1. DNS Resolution Completeness
    if dns_res and (dns_res.resolved_ips or dns_res.nameservers):
        confidence += CONF_DNS_AVAILABLE

    # 2. RDAP / Domain Age Availability
    if rdap_res and rdap_res.created_date is not None:
        confidence += CONF_RDAP_AVAILABLE

    # 3. TLS Certificate Metadata Availability
    if tls_res and tls_res.https_available:
        confidence += CONF_TLS_AVAILABLE

    # 4. Redirect Trace Reached Destination
    if redir_res and not redir_res.blocked_by_ssrf:
        confidence += CONF_REDIRECT_TRACED

    # 5. Threat Intelligence Concordance
    if ti_results:
        successful_ti = [ti for ti in ti_results if ti.status == "success"]
        positive_ti = [ti for ti in successful_ti if ti.is_positive]

        # Multi-provider agreement yields high confidence
        if len(positive_ti) >= 2:
            confidence += CONF_TI_FEEDS_AGREEMENT
        elif len(successful_ti) >= 3:
            confidence += CONF_TI_FEEDS_AGREEMENT / 2

    return round(min(100.0, max(10.0, confidence)), 1)
