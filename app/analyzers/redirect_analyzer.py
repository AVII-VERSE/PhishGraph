"""Hop-by-hop Safe Redirect Analyzer with strict SSRF validation."""

from typing import List, Optional
from urllib.parse import urljoin, urlparse
import httpx
from pydantic import BaseModel, Field
from app.config import get_settings
from app.logging import get_logger
from app.security.url_safety import validate_url_safety

logger = get_logger("phishgraph.analyzers.redirects")


class RedirectHop(BaseModel):
    """Single redirect hop metadata."""

    hop_number: int
    source_url: str
    destination_url: str
    source_domain: str
    destination_domain: str
    status_code: int


class RedirectChainResult(BaseModel):
    """Full redirect trace with risk signals."""

    initial_url: str
    final_url: str
    total_hops: int
    hops: List[RedirectHop] = Field(default_factory=list)
    cross_domain_redirects: int = 0
    blocked_by_ssrf: bool = False
    blocked_reason: Optional[str] = None
    signals: List[str] = Field(default_factory=list)


async def trace_redirect_chain(
    url: str,
    max_redirects: Optional[int] = None,
    timeout: Optional[float] = None,
    http_client: Optional[httpx.AsyncClient] = None,
    allow_private_in_testing: bool = False,
) -> RedirectChainResult:
    """Trace HTTP redirect chain manually with per-hop SSRF validation."""
    settings = get_settings()
    limit = max_redirects or settings.MAX_REDIRECTS
    req_timeout = timeout or settings.HTTP_TIMEOUT_SECONDS

    current_url = url
    hops: List[RedirectHop] = []
    signals: List[str] = []
    cross_domains = 0
    blocked = False
    block_reason: Optional[str] = None

    client = http_client or httpx.AsyncClient(
        follow_redirects=False,
        timeout=req_timeout,
        headers={"User-Agent": "PhishGraph-Defensive-Analyzer/1.0"},
    )

    try:
        for hop_idx in range(1, limit + 1):
            # 1. SSRF Validation before making request
            is_safe, reason, _ = await validate_url_safety(
                current_url,
                allow_private_in_testing=allow_private_in_testing,
            )
            if not is_safe:
                blocked = True
                block_reason = reason or "SSRF check failed"
                signals.append(f"Redirect halted at hop {hop_idx}: {block_reason}")
                logger.warning(f"Redirect to {current_url} blocked by SSRF: {block_reason}")
                break

            # 2. Perform low-impact HEAD or GET
            try:
                resp = await client.head(current_url)
                if resp.status_code in (405, 501):  # Method Not Allowed, fallback to GET
                    resp = await client.get(current_url)
            except httpx.RequestError as exc:
                signals.append(f"Network error at hop {hop_idx}: {exc}")
                break

            # 3. Check for 3xx redirect status
            if resp.is_redirect:
                location = resp.headers.get("Location")
                if not location:
                    break

                next_url = urljoin(current_url, location)
                src_domain = urlparse(current_url).netloc.lower()
                dst_domain = urlparse(next_url).netloc.lower()

                if src_domain != dst_domain:
                    cross_domains += 1

                hops.append(
                    RedirectHop(
                        hop_number=hop_idx,
                        source_url=current_url,
                        destination_url=next_url,
                        source_domain=src_domain,
                        destination_domain=dst_domain,
                        status_code=resp.status_code,
                    )
                )
                current_url = next_url
            else:
                # Terminal destination reached
                break

    finally:
        if http_client is None:
            await client.aclose()

    if cross_domains >= 2:
        signals.append(f"Multiple cross-domain redirects observed ({cross_domains} domain changes)")
    elif cross_domains == 1:
        signals.append("Cross-domain redirect detected")

    if len(hops) >= limit:
        signals.append(f"Exceeded maximum redirect limit ({limit} hops)")

    return RedirectChainResult(
        initial_url=url,
        final_url=current_url,
        total_hops=len(hops),
        hops=hops,
        cross_domain_redirects=cross_domains,
        blocked_by_ssrf=blocked,
        blocked_reason=block_reason,
        signals=signals,
    )
