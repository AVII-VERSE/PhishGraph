"""URL Heuristic & Structural Analyzer."""

import math
from collections import Counter
from typing import List
from urllib.parse import parse_qs, unquote, urlparse
from pydantic import BaseModel, Field

DEFAULT_SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "wallet",
    "payment",
    "bank",
    "banking",
    "confirm",
    "unlock",
    "support",
    "recovery",
    "authenticate",
    "auth",
    "checkpoint",
    "kyc",
    "webscr",
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string (measure of randomness)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class URLFeatures(BaseModel):
    """Extracted heuristic properties of a submitted URL."""

    original_url: str
    hostname: str
    url_length: int
    hostname_length: int
    path_length: int
    subdomain_count: int
    query_param_count: int
    hyphen_count: int
    digit_count: int
    is_ip_hostname: bool
    has_at_symbol: bool
    has_double_slash_in_path: bool
    has_punycode: bool
    path_entropy: float
    query_entropy: float
    suspicious_keywords_found: List[str] = Field(default_factory=list)
    heuristic_signals: List[str] = Field(default_factory=list)


def analyze_url_heuristics(
    url: str,
    keywords: set[str] = DEFAULT_SUSPICIOUS_KEYWORDS,
) -> URLFeatures:
    """Extract structural heuristics and indicators from a URL string."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Subdomain count
    subdomains = [p for p in hostname.split(".") if p]
    # e.g., 'a.b.example.com' has 2 subdomains before 'example.com'
    subdomain_count = max(0, len(subdomains) - 2) if len(subdomains) >= 2 else 0

    # IP address hostname
    is_ip = False
    import ipaddress

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # Symbol checks
    has_at = "@" in url
    has_double_slash = "//" in path
    has_punycode = "xn--" in hostname

    # Entropy
    path_entropy = calculate_shannon_entropy(path)
    query_entropy = calculate_shannon_entropy(query)

    # Keywords in hostname, path, and query
    haystack = f"{hostname} {unquote(path)} {unquote(query)}".lower()
    found_keywords = [kw for kw in keywords if kw in haystack]

    # Flags & signals
    signals: List[str] = []
    if is_ip:
        signals.append("IP-address used as hostname")
    if has_at:
        signals.append("@ symbol present in URL (possible credential masking)")
    if has_double_slash:
        signals.append("Consecutive slashes in path (possible open redirect evasion)")
    if has_punycode:
        signals.append("Punycode (xn--) internationalized domain detected")
    if len(found_keywords) >= 2:
        signals.append(f"Multiple suspicious keywords detected: {', '.join(found_keywords)}")
    elif len(found_keywords) == 1:
        signals.append(f"Suspicious keyword detected: {found_keywords[0]}")
    if subdomain_count >= 3:
        signals.append(f"High subdomain depth ({subdomain_count} subdomains)")
    if path_entropy > 4.2:
        signals.append("High path entropy (possible machine-generated path)")

    query_params = parse_qs(query)

    return URLFeatures(
        original_url=url,
        hostname=hostname,
        url_length=len(url),
        hostname_length=len(hostname),
        path_length=len(path),
        subdomain_count=subdomain_count,
        query_param_count=len(query_params),
        hyphen_count=hostname.count("-"),
        digit_count=sum(c.isdigit() for c in hostname),
        is_ip_hostname=is_ip,
        has_at_symbol=has_at,
        has_double_slash_in_path=has_double_slash,
        has_punycode=has_punycode,
        path_entropy=path_entropy,
        query_entropy=query_entropy,
        suspicious_keywords_found=sorted(found_keywords),
        heuristic_signals=signals,
    )
