"""Brand Impersonation & Typosquatting Analyzer."""

import json
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.logging import get_logger

logger = get_logger("phishgraph.analyzers.brand")

CHAR_SUBSTITUTIONS = {
    "1": "l",
    "0": "o",
    "3": "e",
    "5": "s",
    "@": "a",
    "vv": "w",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Compute Jaro-Winkler string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    transpositions //= 2
    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    # Winkler prefix bonus (up to 4 characters)
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return round(jaro + prefix * 0.1 * (1.0 - jaro), 3)


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions (e.g. paypa1 -> paypal)."""
    res = text.lower()
    for leet, norm in CHAR_SUBSTITUTIONS.items():
        res = res.replace(leet, norm)
    return res


class BrandMatch(BaseModel):
    """Brand similarity detection result."""

    brand_name: str
    similarity_score: float = 0.0
    detection_method: str = "none"
    is_official_domain: bool = False
    matched_string: str = ""
    signals: List[str] = Field(default_factory=list)


class BrandImpersonationResult(BaseModel):
    """Aggregate brand impersonation analysis."""

    domain: str
    matches: List[BrandMatch] = Field(default_factory=list)
    has_brand_impersonation: bool = False
    top_matched_brand: Optional[str] = None
    signals: List[str] = Field(default_factory=list)


def load_brand_dataset(filepath: Optional[str] = None) -> Dict[str, List[str]]:
    """Load known brand-to-official-domain mapping from json."""
    target_path = filepath
    if not target_path:
        base_dir = Path(__file__).resolve().parent.parent
        target_path = str(base_dir / "data" / "brands.json")

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning(f"Could not load brands dataset from {target_path}: {exc}")
        return {
            "paypal": ["paypal.com"],
            "google": ["google.com"],
            "microsoft": ["microsoft.com"],
            "apple": ["apple.com"],
            "amazon": ["amazon.com"],
        }


class BrandAnalyzer:
    """Engine identifying potential brand spoofing in domain names."""

    def __init__(self, brands_map: Optional[Dict[str, List[str]]] = None):
        self.brands_map = brands_map or load_brand_dataset()

    def analyze_domain(self, domain: str) -> BrandImpersonationResult:
        """Analyze a domain against official brand signatures and typosquat variations."""
        dom_clean = domain.lower().strip()
        matches: List[BrandMatch] = []
        overall_signals: List[str] = []

        # Extract domain base (e.g. 'paypa1-login' from 'paypa1-login.example.com')
        parts = dom_clean.split(".")
        labels_to_check = [parts[0]]
        if len(parts) > 2:
            labels_to_check.append(parts[1])
            labels_to_check.append("-".join(parts[:-1]))

        for brand, official_domains in self.brands_map.items():
            # 1. Official domain check
            is_official = False
            for off_dom in official_domains:
                if dom_clean == off_dom or dom_clean.endswith("." + off_dom):
                    is_official = True
                    break

            if is_official:
                matches.append(
                    BrandMatch(
                        brand_name=brand,
                        similarity_score=1.0,
                        detection_method="official_domain_match",
                        is_official_domain=True,
                        matched_string=dom_clean,
                        signals=[f"Verified official domain for {brand.capitalize()}"],
                    )
                )
                continue

            # 2. Check for exact brand keyword in unapproved domain
            normalized_dom = normalize_leetspeak(dom_clean)
            if brand in dom_clean or brand in normalized_dom:
                method = "exact_keyword" if brand in dom_clean else "leetspeak_substitution"
                match_obj = BrandMatch(
                    brand_name=brand,
                    similarity_score=0.95,
                    detection_method=method,
                    is_official_domain=False,
                    matched_string=brand,
                    signals=[
                        f"Potential brand impersonation: Contains '{brand}' ({method}) in non-official domain"
                    ],
                )
                matches.append(match_obj)
                overall_signals.extend(match_obj.signals)
                continue

            # 3. Fuzzy Levenshtein / Jaro-Winkler on domain labels
            for label in labels_to_check:
                # Discard very short or generic labels
                if len(label) < 3:
                    continue

                clean_label = label.replace("-", "")
                norm_label = normalize_leetspeak(clean_label)

                dist = levenshtein_distance(brand, norm_label)
                jw = jaro_winkler_similarity(brand, norm_label)

                # Edit distance 1 (or 2 for longer brand names) and high Jaro-Winkler
                if (dist == 1 and len(brand) >= 4) or (dist == 2 and len(brand) >= 7) or (jw >= 0.88):
                    signals = [
                        f"Fuzzy brand similarity detected: resembles '{brand.capitalize()}' (JW: {jw}, Distance: {dist})"
                    ]
                    match_obj = BrandMatch(
                        brand_name=brand,
                        similarity_score=jw,
                        detection_method="fuzzy_similarity",
                        is_official_domain=False,
                        matched_string=label,
                        signals=signals,
                    )
                    matches.append(match_obj)
                    overall_signals.extend(signals)
                    break

        has_impersonation = any(m for m in matches if not m.is_official_domain)
        top_brand = matches[0].brand_name if matches else None

        return BrandImpersonationResult(
            domain=dom_clean,
            matches=matches,
            has_brand_impersonation=has_impersonation,
            top_matched_brand=top_brand,
            signals=overall_signals,
        )
