"""Database models module."""

from app.db.models.dns_record import DNSRecord
from app.db.models.domain import Domain
from app.db.models.redirect import RedirectRecord
from app.db.models.scan import Scan
from app.db.models.threat_intel import ThreatIntelRecord
from app.db.models.tls_record import TLSRecord
from app.db.models.user import User

__all__ = [
    "User",
    "Scan",
    "Domain",
    "DNSRecord",
    "TLSRecord",
    "RedirectRecord",
    "ThreatIntelRecord",
]
