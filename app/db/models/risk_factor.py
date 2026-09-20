"""Scan Risk Factor database model."""

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class ScanRiskFactor(Base):
    """Specific contributing evidence factor persisted per scan."""

    __tablename__ = "scan_risk_factors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    factor_code: Mapped[str] = mapped_column(String(50), index=True)
    factor_description: Mapped[str] = mapped_column(Text)
    weight: Mapped[float] = mapped_column(Float)
    evidence_source: Mapped[str] = mapped_column(String(50))

    def __repr__(self) -> str:
        return f"<ScanRiskFactor code={self.factor_code} weight=+{self.weight}>"
