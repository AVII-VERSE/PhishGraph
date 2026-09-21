"""Explainable Threat Risk Scoring Engine."""

from typing import List, Optional
from pydantic import BaseModel, Field
from app.analyzers.brand_analyzer import BrandImpersonationResult
from app.analyzers.dga_analyzer import DGAResult
from app.analyzers.dns_analyzer import DNSAnalysisResult
from app.analyzers.domain_analyzer import DomainIntelligenceResult
from app.analyzers.punycode_analyzer import PunycodeAnalysisResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.analyzers.url_analyzer import URLFeatures
from app.scoring.mitre_mapper import MitreMapper, MitreTechnique
from app.scoring.weights import (
    WEIGHT_BRAND_IMPERSONATION,
    WEIGHT_CROSS_DOMAIN_REDIRECT,
    WEIGHT_DGA_ANOMALY,
    WEIGHT_DOMAIN_AGE_UNDER_7_DAYS,
    WEIGHT_DOMAIN_AGE_UNDER_30_DAYS,
    WEIGHT_HIGH_URL_ENTROPY,
    WEIGHT_INVALID_TLS,
    WEIGHT_IP_HOSTNAME,
    WEIGHT_MULTIPLE_REDIRECTS,
    WEIGHT_PUNYCODE_HOMOGRAPH,
    WEIGHT_SELF_SIGNED_TLS,
    WEIGHT_SUSPICIOUS_KEYWORDS_MULTIPLE,
    WEIGHT_SUSPICIOUS_KEYWORDS_SINGLE,
    WEIGHT_TI_MALICIOUS_REPUTATION,
    WEIGHT_TI_PHISHING_FEED_MATCH,
)
from app.threat_intel.base import ThreatIntelResult



class RiskFactorItem(BaseModel):
    """Specific evidence contributor to risk score."""

    factor_code: str
    factor_description: str
    weight: float
    evidence_source: str


class RiskAssessmentResult(BaseModel):
    """Complete explainable risk assessment output."""

    risk_score: float
    risk_level: str  # LOW, MODERATE, HIGH, CRITICAL
    factors: List[RiskFactorItem] = Field(default_factory=list)
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)

    @property
    def formatted_explanation(self) -> str:
        """Render explainable factors breakdown for reports & Telegram."""
        if not self.factors:
            return "No significant risk factors identified."
        lines = [f"+{int(f.weight)} {f.factor_description}" for f in self.factors]
        return "\n".join(lines)


def calculate_risk_score(
    heuristics: URLFeatures,
    dns_res: Optional[DNSAnalysisResult] = None,
    rdap_res: Optional[DomainIntelligenceResult] = None,
    tls_res: Optional[TLSAnalysisResult] = None,
    redir_res: Optional[RedirectChainResult] = None,
    ti_results: Optional[List[ThreatIntelResult]] = None,
    brand_res: Optional[BrandImpersonationResult] = None,
    puny_res: Optional[PunycodeAnalysisResult] = None,
    dga_res: Optional[DGAResult] = None,
) -> RiskAssessmentResult:
    """Calculate transparent, explainable 0–100 threat risk score."""
    factors: List[RiskFactorItem] = []
    total_score = 0.0


    # 1. Threat Intelligence Contributions
    for ti in ti_results or []:
        if ti.malicious:
            desc = f"{ti.provider.upper()} listed indicator as malicious"
            if ti.labels:
                desc += f" ({', '.join(ti.labels[:2])})"
            weight = WEIGHT_TI_PHISHING_FEED_MATCH if "phishing" in str(ti.labels).lower() else WEIGHT_TI_MALICIOUS_REPUTATION
            factors.append(
                RiskFactorItem(
                    factor_code="TI_MALICIOUS_MATCH",
                    factor_description=desc,
                    weight=weight,
                    evidence_source=ti.provider,
                )
            )
            total_score += weight
            break  # Apply primary TI match weight, supporting feeds boost confidence

    # 2. Brand Impersonation & Typosquatting
    if brand_res and brand_res.has_brand_impersonation:
        for match in brand_res.matches:
            if not match.is_official_domain:
                factors.append(
                    RiskFactorItem(
                        factor_code="BRAND_IMPERSONATION",
                        factor_description=f"Brand impersonation targeting {match.brand_name.capitalize()}",
                        weight=WEIGHT_BRAND_IMPERSONATION,
                        evidence_source="brand_engine",
                    )
                )
                total_score += WEIGHT_BRAND_IMPERSONATION
                break

    # 3. Punycode & Homographs
    if puny_res and (puny_res.is_punycode or puny_res.is_mixed_script):
        desc = "Internationalized punycode domain detected"
        if puny_res.is_mixed_script:
            desc = f"Mixed-script homoglyph domain ({', '.join(puny_res.scripts_detected)})"
        factors.append(
            RiskFactorItem(
                factor_code="PUNYCODE_HOMOGLYPH",
                factor_description=desc,
                weight=WEIGHT_PUNYCODE_HOMOGRAPH,
                evidence_source="punycode_engine",
            )
        )
        total_score += WEIGHT_PUNYCODE_HOMOGRAPH

    # 4. Domain Age
    if rdap_res and rdap_res.domain_age_days is not None:
        if rdap_res.domain_age_days < 7:
            factors.append(
                RiskFactorItem(
                    factor_code="DOMAIN_AGE_UNDER_7",
                    factor_description=f"Domain registered only {rdap_res.domain_age_days} days ago",
                    weight=WEIGHT_DOMAIN_AGE_UNDER_7_DAYS,
                    evidence_source="rdap_intelligence",
                )
            )
            total_score += WEIGHT_DOMAIN_AGE_UNDER_7_DAYS
        elif rdap_res.domain_age_days < 30:
            factors.append(
                RiskFactorItem(
                    factor_code="DOMAIN_AGE_UNDER_30",
                    factor_description=f"Domain registered recently ({rdap_res.domain_age_days} days ago)",
                    weight=WEIGHT_DOMAIN_AGE_UNDER_30_DAYS,
                    evidence_source="rdap_intelligence",
                )
            )
            total_score += WEIGHT_DOMAIN_AGE_UNDER_30_DAYS

    # 5. URL Heuristic Indicators
    if heuristics.is_ip_hostname:
        factors.append(
            RiskFactorItem(
                factor_code="IP_HOSTNAME",
                factor_description="Raw IP address used as URL hostname",
                weight=WEIGHT_IP_HOSTNAME,
                evidence_source="url_heuristics",
            )
        )
        total_score += WEIGHT_IP_HOSTNAME

    if len(heuristics.suspicious_keywords_found) >= 2:
        factors.append(
            RiskFactorItem(
                factor_code="KEYWORDS_MULTIPLE",
                factor_description=f"Multiple lure keywords ({', '.join(heuristics.suspicious_keywords_found[:3])})",
                weight=WEIGHT_SUSPICIOUS_KEYWORDS_MULTIPLE,
                evidence_source="url_heuristics",
            )
        )
        total_score += WEIGHT_SUSPICIOUS_KEYWORDS_MULTIPLE
    elif len(heuristics.suspicious_keywords_found) == 1:
        factors.append(
            RiskFactorItem(
                factor_code="KEYWORDS_SINGLE",
                factor_description=f"Suspicious keyword ({heuristics.suspicious_keywords_found[0]})",
                weight=WEIGHT_SUSPICIOUS_KEYWORDS_SINGLE,
                evidence_source="url_heuristics",
            )
        )
        total_score += WEIGHT_SUSPICIOUS_KEYWORDS_SINGLE

    if heuristics.path_entropy > 4.2:
        factors.append(
            RiskFactorItem(
                factor_code="HIGH_ENTROPY",
                factor_description=f"High path entropy ({heuristics.path_entropy})",
                weight=WEIGHT_HIGH_URL_ENTROPY,
                evidence_source="url_heuristics",
            )
        )
        total_score += WEIGHT_HIGH_URL_ENTROPY

    if getattr(heuristics, "is_high_abuse_tld", False):
        factors.append(
            RiskFactorItem(
                factor_code="HIGH_ABUSE_TLD",
                factor_description="High-abuse top-level domain frequently linked to phishing",
                weight=10.0,
                evidence_source="url_heuristics",
            )
        )
        total_score += 10.0

    if getattr(heuristics, "has_brand_subdomain", False):
        factors.append(
            RiskFactorItem(
                factor_code="BRAND_SUBDOMAIN_SPOOF",
                factor_description="Brand keyword disguised in subdomain structure",
                weight=18.0,
                evidence_source="url_heuristics",
            )
        )
        total_score += 18.0

    # 6. TLS Indicators
    if tls_res:
        if tls_res.is_self_signed:
            factors.append(
                RiskFactorItem(
                    factor_code="TLS_SELF_SIGNED",
                    factor_description="Self-signed TLS certificate presented",
                    weight=WEIGHT_SELF_SIGNED_TLS,
                    evidence_source="tls_inspection",
                )
            )
            total_score += WEIGHT_SELF_SIGNED_TLS
        elif not tls_res.is_valid and tls_res.https_available:
            factors.append(
                RiskFactorItem(
                    factor_code="TLS_INVALID_CHAIN",
                    factor_description="Untrusted or invalid TLS certificate chain",
                    weight=WEIGHT_INVALID_TLS,
                    evidence_source="tls_inspection",
                )
            )
            total_score += WEIGHT_INVALID_TLS

    # 7. Redirect Chain
    if redir_res:
        if redir_res.cross_domain_redirects >= 2:
            factors.append(
                RiskFactorItem(
                    factor_code="REDIRECT_MULTIPLE_CROSS_DOMAIN",
                    factor_description=f"Multiple cross-domain redirects ({redir_res.cross_domain_redirects} hops)",
                    weight=WEIGHT_MULTIPLE_REDIRECTS,
                    evidence_source="redirect_trace",
                )
            )
            total_score += WEIGHT_MULTIPLE_REDIRECTS
        elif redir_res.cross_domain_redirects == 1:
            factors.append(
                RiskFactorItem(
                    factor_code="REDIRECT_CROSS_DOMAIN",
                    factor_description="Cross-domain redirection observed",
                    weight=WEIGHT_CROSS_DOMAIN_REDIRECT,
                    evidence_source="redirect_trace",
                )
            )
            total_score += WEIGHT_CROSS_DOMAIN_REDIRECT

    # 8. DGA (Domain Generation Algorithm) & High-Entropy Anomaly
    if dga_res and dga_res.is_dga_suspected:
        factors.append(
            RiskFactorItem(
                factor_code="DGA_ANOMALY",
                factor_description="Suspicious Domain Generation Algorithm (DGA) pattern detected",
                weight=WEIGHT_DGA_ANOMALY,
                evidence_source="dga_analyzer",
            )
        )
        total_score += WEIGHT_DGA_ANOMALY

    # Map MITRE ATT&CK Matrix
    mitre_list = MitreMapper.map_indicators(
        heuristics=heuristics,
        brand_res=brand_res,
        dga_res=dga_res,
        tls_res=tls_res,
        redir_res=redir_res,
        ti_results=ti_results,
    )

    # Cap total score at 100
    capped_score = min(100.0, max(0.0, total_score))

    if capped_score >= 75:
        level = "CRITICAL"
    elif capped_score >= 50:
        level = "HIGH"
    elif capped_score >= 25:
        level = "MODERATE"
    else:
        level = "LOW"

    return RiskAssessmentResult(
        risk_score=round(capped_score, 1),
        risk_level=level,
        factors=factors,
        mitre_techniques=mitre_list,
    )

