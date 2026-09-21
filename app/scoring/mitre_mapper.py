"""MITRE ATT&CK Framework Mapping for Phishing & Infrastructure Indicators.

Maps observed indicators (typosquatting, brand spoofing, DGA, redirects,
malicious TLS, evasive schemes) directly to standard MITRE ATT&CK techniques.
"""

from dataclasses import dataclass
from typing import List, Optional
from app.analyzers.brand_analyzer import BrandImpersonationResult
from app.analyzers.dga_analyzer import DGAResult
from app.analyzers.redirect_analyzer import RedirectChainResult
from app.analyzers.tls_analyzer import TLSAnalysisResult
from app.analyzers.url_analyzer import URLFeatures
from app.threat_intel.base import ThreatIntelResult


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique reference."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str


class MitreMapper:
    """Maps security observations to MITRE ATT&CK Matrix."""

    @staticmethod
    def map_indicators(
        heuristics: URLFeatures,
        brand_res: Optional[BrandImpersonationResult] = None,
        dga_res: Optional[DGAResult] = None,
        tls_res: Optional[TLSAnalysisResult] = None,
        redir_res: Optional[RedirectChainResult] = None,
        ti_results: Optional[List[ThreatIntelResult]] = None,
    ) -> List[MitreTechnique]:
        """Generate deduplicated list of MITRE techniques matching evidence."""
        techniques: dict[str, MitreTechnique] = {}

        # 1. Spearphishing Link (Always relevant when link distribution is observed)
        techniques["T1566.002"] = MitreTechnique(
            technique_id="T1566.002",
            technique_name="Phishing: Spearphishing Link",
            tactic="Initial Access",
            description="Adversaries send malicious links to entice targets to visit a malicious website.",
        )

        # 2. Acquire Infrastructure: Domains
        techniques["T1583.001"] = MitreTechnique(
            technique_id="T1583.001",
            technique_name="Acquire Infrastructure: Domains",
            tactic="Resource Development",
            description="Adversaries acquire domains that can be used during targeting.",
        )

        # 3. Brand Impersonation / Masquerading
        if brand_res and brand_res.has_brand_impersonation:
            techniques["T1036.007"] = MitreTechnique(
                technique_id="T1036.007",
                technique_name="Masquerading: Double File Extension / Name Squatting",
                tactic="Defense Evasion",
                description="Adversaries mimic legitimate brands or typosquat domain names to deceive users.",
            )

        # 4. Domain Generation Algorithms (DGA)
        if dga_res and dga_res.is_dga_suspected:
            techniques["T1568.002"] = MitreTechnique(
                technique_id="T1568.002",
                technique_name="Dynamic Resolution: Domain Generation Algorithms",
                tactic="Command and Control",
                description="Adversaries use DGAs to dynamically resolve domain names and evade static blocklists.",
            )

        # 5. Evasive Redirect Chains
        if redir_res and (redir_res.total_hops > 1 or redir_res.cross_domain_redirects > 0):
            techniques["T1071.001"] = MitreTechnique(
                technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
                tactic="Command and Control",
                description="Adversaries use multi-hop web redirects to evade static perimeter analysis.",
            )


        # 6. Fraudulent / Invalid TLS Certificates
        if tls_res and (not tls_res.hostname_matches or tls_res.is_self_signed):
            techniques["T1588.004"] = MitreTechnique(
                technique_id="T1588.004",
                technique_name="Obtain Capabilities: Digital Certificates",
                tactic="Resource Development",
                description="Adversaries acquire or forge SSL/TLS certificates to disguise traffic as encrypted and authentic.",
            )

        # 7. Threat Intelligence Feeds confirm Malware / Botnet
        for ti in ti_results or []:
            if ti.malicious:
                techniques["T1204.001"] = MitreTechnique(
                    technique_id="T1204.001",
                    technique_name="User Execution: Malicious Link",
                    tactic="Execution",
                    description="Adversaries rely on users clicking malicious links to initiate code execution or credential harvesting.",
                )
                break

        return list(techniques.values())
