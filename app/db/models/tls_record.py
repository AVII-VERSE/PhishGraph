"""TLS Record database model."""

from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class TLSRecord(Base):
    """TLS Certificate record captured during scan."""

    __tablename__ = "tls_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    issuer: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    common_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    hostname_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    certificate_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:
        return f"<TLSRecord cn={self.common_name} issuer={self.issuer[:20] if self.issuer else None}>"
