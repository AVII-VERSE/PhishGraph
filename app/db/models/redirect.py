"""Redirect Record database model."""

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class RedirectRecord(Base):
    """Trace of a redirect hop observed during scan."""

    __tablename__ = "redirects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    hop_number: Mapped[int] = mapped_column(Integer)
    source_url: Mapped[str] = mapped_column(Text)
    destination_url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer)

    def __repr__(self) -> str:
        return f"<RedirectRecord #{self.hop_number} {self.status_code} {self.source_url} -> {self.destination_url}>"
