"""Threat Intelligence provider interface and normalized schemas."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatIntelResult(BaseModel):
    """Normalized threat intelligence indicator record."""

    provider: str
    status: str = "success"  # success, skipped_no_key, not_found, timeout, rate_limited, error
    malicious: bool = False
    suspicious: bool = False
    score: int = 0  # 0 to 100 severity or detection tally
    labels: List[str] = Field(default_factory=list)
    raw_reference: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_positive(self) -> bool:
        """True if the provider marked the indicator as malicious or suspicious."""
        return self.malicious or self.suspicious or self.score > 0


class ThreatIntelProvider(ABC):
    """Abstract base provider for threat intelligence lookups."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider identifier."""
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> ThreatIntelResult:
        """Query provider with full target URL."""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """Query provider with domain name."""
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Query provider with IP address."""
        pass
