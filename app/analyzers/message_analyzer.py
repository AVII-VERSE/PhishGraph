"""Forwarded message and lure text social-engineering analyzer."""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from app.analyzers.brand_analyzer import BrandAnalyzer
from app.services.scan_service import extract_urls_from_text

# Urgency and lure keywords commonly observed in phishing lures (Section 5.7)
URGENCY_PATTERNS = [
    (re.compile(r"\b(immediately|urgent|urgently|right away|asap)\b", re.I), "High urgency language"),
    (re.compile(r"\b(locked|lockout|suspended|disabled|frozen|restricted|terminated)\b", re.I), "Account lockout or restriction pressure"),
    (re.compile(r"\b(verify|verification|validate|reactivate|authenticate|confirm)\b", re.I), "Credential or identity verification lure"),
    (re.compile(r"\b(24\s*hours?|48\s*hours?|within\s+\d+\s*(?:mins?|minutes?|hours?|days?))\b", re.I), "Artificial time-window pressure"),
    (re.compile(r"\b(unauthorized|suspicious activity|fraudulent|security alert|breach)\b", re.I), "Security alert or false threat trigger"),
    (re.compile(r"\b(action required|important notice|attention required)\b", re.I), "Call-to-action pressure"),
    (re.compile(r"\b(refund|prize|winner|claim reward|invoice attached)\b", re.I), "Financial lure or prize pretext"),
]


@dataclass
class MessageAnalysisResult:
    """Summary of social-engineering indicators extracted from message text."""

    raw_text: str
    urls: List[str] = field(default_factory=list)
    urgency_signals: List[str] = field(default_factory=list)
    claimed_brands: List[str] = field(default_factory=list)
    brand_mismatch: bool = False
    mismatched_brand_details: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    @property
    def has_lure_signals(self) -> bool:
        return bool(self.urgency_signals or self.brand_mismatch)


class MessageAnalyzer:
    """Analyzes message text for social-engineering, urgency, and brand spoof pretexts."""

    def __init__(self, brand_analyzer: Optional[BrandAnalyzer] = None) -> None:
        self.brand_analyzer = brand_analyzer or BrandAnalyzer()

    def analyze_text(self, text: str) -> MessageAnalysisResult:
        """Analyze message text and extract social engineering signals."""
        urls = extract_urls_from_text(text)
        urgency_signals: List[str] = []

        # 1. Detect Urgency Patterns
        for pattern, desc in URGENCY_PATTERNS:
            match = pattern.search(text)
            if match:
                urgency_signals.append(f"{desc}: “{match.group(0)}”")

        # 2. Identify Claimed Brand Mentions
        claimed_brands: List[str] = []
        lower_text = text.lower()
        for brand_name in self.brand_analyzer.brands:
            # Word-boundary check for brand name
            pattern = rf"\b{re.escape(brand_name)}\b"
            if re.search(pattern, lower_text):
                claimed_brands.append(brand_name)

        # 3. Cross-reference Claimed Brands vs Extracted URLs
        brand_mismatch = False
        mismatches: List[str] = []

        if claimed_brands and urls:
            for url in urls:
                try:
                    domain = urlparse(url).netloc.split(":")[0].lower()
                except Exception:
                    continue

                for brand in claimed_brands:
                    official_domains = self.brand_analyzer.brands.get(brand, [])
                    # Check if domain matches official domain
                    is_official = any(
                        domain == off or domain.endswith("." + off)
                        for off in official_domains
                    )
                    if not is_official:
                        brand_mismatch = True
                        mismatches.append(
                            f"Claimed brand '{brand.capitalize()}' does not match destination domain `{domain}`"
                        )

        # 4. Compile Combined Findings
        findings: List[str] = []
        findings.extend(urgency_signals)
        if urls:
            findings.append(f"External link(s) embedded ({len(urls)} found)")
        findings.extend(mismatches)

        return MessageAnalysisResult(
            raw_text=text,
            urls=urls,
            urgency_signals=urgency_signals,
            claimed_brands=claimed_brands,
            brand_mismatch=brand_mismatch,
            mismatched_brand_details=mismatches,
            findings=findings,
        )
