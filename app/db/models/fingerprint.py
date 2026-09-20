"""Fingerprint database model."""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Fingerprint(Base):
    """Infrastructure fingerprint record for a scan."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    ip_set: Mapped[List[str]] = mapped_column(JSON, default=list)
    asn: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    nameserver_set: Mapped[List[str]] = mapped_column(JSON, default=list)
    registrar: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    tls_serial: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    tls_issuer: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    favicon_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    page_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    redirect_domain_set: Mapped[List[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<Fingerprint id={self.id} domain={self.domain} asn={self.asn}>"
