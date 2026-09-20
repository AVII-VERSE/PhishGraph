"""TLS/SSL Certificate metadata and handshake analyzer."""

import asyncio
import datetime
import ssl
from typing import List, Optional
from pydantic import BaseModel, Field
from app.logging import get_logger

logger = get_logger("phishgraph.analyzers.tls")


class TLSAnalysisResult(BaseModel):
    """Normalized TLS certificate inspection findings."""

    domain: str
    port: int = 443
    https_available: bool = False
    is_valid: bool = False
    hostname_matches: bool = False
    is_self_signed: bool = False
    is_expired: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    common_name: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[datetime.datetime] = None
    valid_until: Optional[datetime.datetime] = None
    days_remaining: Optional[int] = None
    tls_version: Optional[str] = None
    sans: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)


def parse_asn1_date(date_str: str) -> Optional[datetime.datetime]:
    """Parse standard ASN1/OpenSSL date strings (e.g. 'Jan 15 12:00:00 2026 GMT')."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y%m%d%H%M%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt).replace(tzinfo=datetime.timezone.utc)
        except Exception:
            pass
    return None


async def inspect_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 4.0,
) -> TLSAnalysisResult:
    """Connect via TLS socket, extract peer certificate, and analyze validity."""
    result = TLSAnalysisResult(domain=hostname, port=port)

    ssl_context = ssl.create_default_context()
    # We allow unverified context fallback to inspect invalid/self-signed certs
    ssl_context_lax = ssl._create_unverified_context()

    cert: Optional[dict] = None
    negotiated_version: Optional[str] = None
    is_valid_chain = False

    # 1. Attempt strict verified handshake
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ssl_context, server_hostname=hostname),
            timeout=timeout,
        )
        is_valid_chain = True
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert = ssl_obj.getpeercert()
            negotiated_version = ssl_obj.version()
        writer.close()
        await writer.wait_closed()
    except Exception as strict_err:
        logger.debug(f"Strict TLS handshake failed for {hostname}: {strict_err}")
        # 2. Fallback to lax handshake to still retrieve certificate metadata
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ssl_context_lax, server_hostname=hostname),
                timeout=timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                negotiated_version = ssl_obj.version()
            writer.close()
            await writer.wait_closed()
        except Exception as lax_err:
            logger.debug(f"TLS connection unreachable for {hostname}:{port}: {lax_err}")
            result.signals.append("HTTPS / TLS service is not reachable on port 443")
            return result

    if not cert:
        result.signals.append("No TLS certificate presented by server")
        return result

    result.https_available = True
    result.tls_version = negotiated_version
    result.is_valid = is_valid_chain

    # Parse Subject and Common Name
    subject_tuples = cert.get("subject", ())
    subject_parts = []
    for rdn in subject_tuples:
        for key, val in rdn:
            subject_parts.append(f"{key}={val}")
            if key == "commonName":
                result.common_name = val
    result.subject = ", ".join(subject_parts)

    # Parse Issuer
    issuer_tuples = cert.get("issuer", ())
    issuer_parts = []
    for rdn in issuer_tuples:
        for key, val in rdn:
            issuer_parts.append(f"{key}={val}")
    result.issuer = ", ".join(issuer_parts)

    # Serial Number
    raw_serial = cert.get("serialNumber")
    if raw_serial:
        result.serial_number = str(raw_serial)

    # SANs
    sans: List[str] = []
    for san_type, san_val in cert.get("subjectAltName", ()):
        if san_type.lower() == "dns":
            sans.append(san_val)
    result.sans = sans

    # Dates and Expiration
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")

    if not_before_str:
        result.valid_from = parse_asn1_date(not_before_str)
    if not_after_str:
        result.valid_until = parse_asn1_date(not_after_str)

    if result.valid_until:
        days_rem = (result.valid_until - now).days
        result.days_remaining = days_rem
        if days_rem < 0:
            result.is_expired = True
            result.signals.append("TLS Certificate has expired")
        elif days_rem < 14:
            result.signals.append(f"TLS Certificate expires soon ({days_rem} days remaining)")

    # Hostname match check
    if result.common_name:
        matched = False
        target_h = hostname.lower()
        candidates = [result.common_name.lower()] + [s.lower() for s in result.sans]
        for cand in candidates:
            if cand == target_h or (cand.startswith("*.") and target_h.endswith(cand[1:])):
                matched = True
                break
        result.hostname_matches = matched
        if not matched:
            result.signals.append(f"Certificate hostname mismatch for {hostname}")

    # Self-signed indicator
    if result.subject and result.issuer and result.subject == result.issuer:
        result.is_self_signed = True
        result.signals.append("Self-signed TLS certificate detected")

    if not result.is_valid and not result.signals:
        result.signals.append("Untrusted or invalid TLS certificate chain")

    return result
