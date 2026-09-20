"""DNS Record database model."""

from typing import Optional
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class DNSRecord(Base):
    """DNS record snapshot associated with a scan."""

    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    record_type: Mapped[str] = mapped_column(String(10), index=True)
    name: Mapped[str] = mapped_column(String(255))
    value: Mapped[str] = mapped_column(Text)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:
        return f"<DNSRecord {self.record_type} {self.name} -> {self.value[:30]}>"
