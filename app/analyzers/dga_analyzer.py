"""DGA (Domain Generation Algorithm) & High-Entropy Anomaly Analyzer.

Detects algorithmically generated domains used by modern botnets (FluBot, Emotet,
Mirai) and phishing campaigns via character entropy, consonant-to-vowel ratios,
and statistical n-gram irregularities.
"""

import math
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class DGAResult:
    """Detection results for algorithmically generated domains."""

    is_dga_suspected: bool
    dga_confidence: float  # 0.0 to 1.0
    entropy: float
    vowel_ratio: float
    longest_consonant_sequence: int
    signals: List[str]


def compute_entropy(text: str) -> float:
    """Calculate Shannon entropy for text."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def analyze_dga(domain: str) -> DGAResult:
    """Analyze domain name for DGA patterns and pronounceability anomalies."""
    signals: List[str] = []
    clean_dom = domain.lower().strip()
    
    # Extract registered label (SLD) without TLD
    parts = clean_dom.split(".")
    sld = parts[0] if parts else clean_dom
    
    # Ignore very short domains
    if len(sld) <= 5:
        return DGAResult(
            is_dga_suspected=False,
            dga_confidence=0.0,
            entropy=compute_entropy(sld),
            vowel_ratio=0.5,
            longest_consonant_sequence=1,
            signals=[],
        )

    # 1. Entropy computation
    entropy = compute_entropy(sld)
    
    # 2. Vowel to Consonant Ratio
    vowels = set("aeiou")
    vowel_count = sum(1 for c in sld if c in vowels)
    alpha_chars = [c for c in sld if c.isalpha()]
    total_alpha = len(alpha_chars)
    vowel_ratio = vowel_count / total_alpha if total_alpha > 0 else 0.0

    # 3. Longest consecutive consonant run
    max_consonants = 0
    current_consonants = 0
    for c in sld:
        if c.isalpha() and c not in vowels:
            current_consonants += 1
            max_consonants = max(max_consonants, current_consonants)
        else:
            current_consonants = 0

    # 4. Digit count ratio in SLD
    digits = sum(1 for c in sld if c.isdigit())
    digit_ratio = digits / len(sld)

    confidence = 0.0
    
    # High entropy threshold for typical English domains is ~3.2-3.4
    if entropy >= 3.3 and len(sld) >= 8:
        confidence += 0.35
        signals.append(f"High character entropy ({entropy}) indicates algorithmically randomized string")

    # Unnatural consonant cluster (e.g. 'rkfxzqp')
    if max_consonants >= 4:
        confidence += 0.30
        signals.append(f"Unnatural consonant cluster detected ({max_consonants} consecutive consonants)")

    # Extremely low or high vowel ratio
    if vowel_ratio < 0.15 and total_alpha >= 5:
        confidence += 0.30
        signals.append(f"Abnormally low vowel frequency ({vowel_ratio:.2f}) indicates non-human pronounceability")
    elif vowel_ratio > 0.70 and total_alpha >= 6:
        confidence += 0.20
        signals.append(f"Abnormally high vowel distribution ({vowel_ratio:.2f})")

    # Excessive digits mixed into label
    if digit_ratio > 0.25 and len(sld) >= 6:
        confidence += 0.25
        signals.append(f"High numerical density in domain name ({digit_ratio:.0%})")


    dga_confidence = min(1.0, round(confidence, 2))
    is_dga = dga_confidence >= 0.50

    return DGAResult(
        is_dga_suspected=is_dga,
        dga_confidence=dga_confidence,
        entropy=entropy,
        vowel_ratio=round(vowel_ratio, 2),
        longest_consonant_sequence=max_consonants,
        signals=signals,
    )
