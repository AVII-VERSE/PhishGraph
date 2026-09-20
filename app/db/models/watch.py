"""Watch database model for URL monitoring and risk drift detection."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Watch(Base):
    """Monitored target URL with periodic drift evaluation."""

    __tablename__ = "watches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    interval_hours: Mapped[int] = mapped_column(Integer, default=12)
    last_scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_risk_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<Watch id={self.id} domain={self.domain} active={self.active} risk={self.last_risk_score}>"
