"""Punycode and Homograph visual similarity analyzer."""

import unicodedata
from typing import List, Optional
import idna
from pydantic import BaseModel, Field


class PunycodeAnalysisResult(BaseModel):
    """Punycode and internationalized domain name analysis."""

    domain: str
    is_punycode: bool = False
    unicode_domain: Optional[str] = None
    scripts_detected: List[str] = Field(default_factory=list)
    is_mixed_script: bool = False
    signals: List[str] = Field(default_factory=list)


def get_character_script(char: str) -> str:
    """Identify the script name for a unicode character."""
    name = unicodedata.name(char, "")
    if "CYRILLIC" in name:
        return "Cyrillic"
    elif "GREEK" in name:
        return "Greek"
    elif "ARABIC" in name:
        return "Arabic"
    elif "HEBREW" in name:
        return "Hebrew"
    elif "LATIN" in name:
        return "Latin"
    elif char.isalnum():
        return "Other"
    return "Common"


def analyze_punycode_and_homographs(domain: str) -> PunycodeAnalysisResult:
    """Analyze domain for punycode prefix (xn--) and cross-script homoglyphs."""
    domain_lower = domain.lower()
    is_puny = "xn--" in domain_lower
    unicode_form: Optional[str] = None
    signals: List[str] = []
    scripts: set[str] = set()

    if is_puny:
        labels = domain_lower.split(".")
        decoded_labels = []
        for lbl in labels:
            if lbl.startswith("xn--"):
                try:
                    decoded_labels.append(idna.decode(lbl))
                except Exception:
                    try:
                        import codecs
                        decoded_labels.append(codecs.decode(lbl[4:].encode("ascii"), "punycode"))
                    except Exception:
                        decoded_labels.append(lbl)
            else:
                decoded_labels.append(lbl)
        unicode_form = ".".join(decoded_labels)
        signals.append(f"Internationalized Domain (IDN): ASCII `{domain_lower}` decodes to `{unicode_form}`")

    target_text = unicode_form if unicode_form else domain_lower
    for char in target_text:
        if char not in ".-":
            script = get_character_script(char)
            if script not in ("Common", "Other"):
                scripts.add(script)

    is_mixed = len(scripts) > 1
    if is_mixed:
        signals.append(f"Mixed-script homograph detected across: {', '.join(sorted(scripts))}")

    return PunycodeAnalysisResult(
        domain=domain_lower,
        is_punycode=is_puny,
        unicode_domain=unicode_form,
        scripts_detected=sorted(list(scripts)),
        is_mixed_script=is_mixed,
        signals=signals,
    )
