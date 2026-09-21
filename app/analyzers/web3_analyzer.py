"""Web3 & Crypto Wallet Drainer Detection Engine.

Detects cryptocurrency phishing, malicious smart-contract approval traps
(Permit2, Seaport, setApprovalForAll), and fraudulent Web3 claim portals.
"""

from dataclasses import dataclass
from typing import List, Optional
import re

DRAINER_KEYWORDS = {
    "airdrop",
    "claim",
    "mint",
    "whitelist",
    "presale",
    "permit2",
    "seaport",
    "drainer",
    "walletconnect",
    "metamask",
    "phantom",
    "trustwallet",
    "keplr",
    "ledger-live",
    "token-approval",
}

DRAINER_SCRIPT_PATTERNS = [
    r"eth_signTypedData_v4",
    r"setApprovalForAll",
    r"increaseAllowance",
    r"permit2",
    r"0x000000000022d473030f116ddee9f6b43ac78ba3",  # Canonical Permit2 address
    r"inferno-drainer",
    r"angel-drainer",
    r"pink-drainer",
    r"ms_init\(\)",
]


@dataclass
class Web3ThreatResult:
    """Crypto drainer and Web3 impersonation analysis result."""

    is_crypto_phishing: bool
    drainer_confidence: float
    detected_keywords: List[str]
    detected_scripts: List[str]
    signals: List[str]


class Web3Analyzer:
    """Detects malicious Web3 infrastructure and wallet-draining tactics."""

    @staticmethod
    def analyze_url_and_content(
        url: str,
        html_content: Optional[str] = None,
    ) -> Web3ThreatResult:
        """Scan URL structure and optional HTML snippet for drainer indicators."""
        clean_url = url.lower()
        found_keywords: List[str] = []
        found_scripts: List[str] = []
        signals: List[str] = []

        # 1. Inspect URL for crypto drainer lure patterns
        for kw in DRAINER_KEYWORDS:
            if kw in clean_url:
                found_keywords.append(kw)

        confidence = 0.0

        if len(found_keywords) >= 2:
            confidence += 0.45
            signals.append(f"Multiple Web3/crypto lure keywords detected: {', '.join(found_keywords[:3])}")
        elif len(found_keywords) == 1:
            confidence += 0.20
            signals.append(f"Web3 lure keyword observed: {found_keywords[0]}")

        # 2. Inspect HTML scripts if provided
        if html_content:
            for pattern in DRAINER_SCRIPT_PATTERNS:
                if re.search(pattern, html_content, re.IGNORECASE):
                    found_scripts.append(pattern)
                    confidence += 0.35
                    signals.append(f"Malicious wallet drainer contract signature detected: {pattern}")

        # Drainers frequently use high-risk TLDs (.xyz, .top, .live, .claims)
        if any(tld in clean_url for tld in [".xyz", ".claims", ".top", ".buzz", ".live", ".cfd"]):
            if found_keywords:
                confidence += 0.20
                signals.append("High-abuse TLD combined with Web3 lure tokens")

        final_confidence = min(1.0, round(confidence, 2))
        is_threat = final_confidence >= 0.40

        return Web3ThreatResult(
            is_crypto_phishing=is_threat,
            drainer_confidence=final_confidence,
            detected_keywords=found_keywords,
            detected_scripts=found_scripts,
            signals=signals,
        )
