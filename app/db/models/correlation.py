"""Correlation database model."""

from datetime import datetime, timezone
from typing import List
from sqlalchemy import DateTime, ForeignKey, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Correlation(Base):
    """Correlation relationship between two scans."""

    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    correlation_score: Mapped[int] = mapped_column(Integer)
    relationship_types: Mapped[List[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<Correlation source={self.source_scan_id} target={self.target_scan_id} score={self.correlation_score}>"
