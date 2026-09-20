"""Threat Intelligence Result database model."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class ThreatIntelRecord(Base):
    """Normalized threat intelligence provider finding stored per scan."""

    __tablename__ = "threat_intel_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(50), index=True)
    provider_status: Mapped[str] = mapped_column(String(50))
    malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_score: Mapped[int] = mapped_column(Integer, default=0)
    labels: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON or comma-separated
    reference_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelRecord provider={self.provider} mal={self.malicious} score={self.provider_score}>"
