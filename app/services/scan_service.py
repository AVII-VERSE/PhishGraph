"""Scan orchestration service managing user tracking and scan lifecycles."""

import re
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.domain import Domain
from app.db.models.scan import Scan
from app.db.models.user import User
from app.logging import get_logger, scan_id_ctx, user_id_ctx

logger = get_logger("phishgraph.scan_service")

# Regex to detect URLs in plain text or forwarded messages
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs present in a given string."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def parse_and_validate_url(raw_url: str) -> Tuple[str, str]:
    """
    Validate and extract normalized URL and domain.
    Returns: (normalized_url, domain)
    Raises: ValueError if URL is invalid or scheme is unsupported.
    """
    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL structure: {raw_url}")

    domain = parsed.hostname or parsed.netloc.split(":")[0]
    domain = domain.lower()

    # Minimal domain validation
    if "." not in domain and domain != "localhost":
        raise ValueError(f"Invalid domain format: {domain}")

    return cleaned, domain


def generate_scan_id() -> str:
    """Generate human-readable scan ID according to PhishGraph spec (e.g., SCAN-2026-000123)."""
    current_year = datetime.now(timezone.utc).year
    short_hash = uuid.uuid4().hex[:6].upper()
    return f"SCAN-{current_year}-{short_hash}"


class ScanService:
    """Service handling scan creation, execution, and user state."""

    @staticmethod
    async def get_or_create_user(
        session: AsyncSession,
        telegram_user_id: int,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
    ) -> User:
        """Retrieve existing user or register a new one upon Telegram interaction."""
        stmt = select(User).where(User.telegram_user_id == telegram_user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if user:
            # Update last_seen and mutable profile info
            user.last_seen_at = datetime.now(timezone.utc)
            if username:
                user.username = username
            if first_name:
                user.first_name = first_name
            await session.commit()
            return user

        user = User(
            telegram_user_id=telegram_user_id,
            username=username,
            first_name=first_name,
            created_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        logger.info(f"Registered new Telegram user {telegram_user_id} (@{username})")
        return user

    @staticmethod
    async def create_scan(
        session: AsyncSession,
        raw_url: str,
        user_id: Optional[int] = None,
    ) -> Scan:
        """Parse target URL and persist a new Scan record in 'pending' status."""
        normalized_url, domain = parse_and_validate_url(raw_url)
        scan_uuid = generate_scan_id()

        scan = Scan(
            scan_uuid=scan_uuid,
            user_id=user_id,
            original_url=raw_url,
            normalized_url=normalized_url,
            domain=domain,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Ensure domain entity exists in tracking database
        domain_stmt = select(Domain).where(Domain.domain == domain)
        dom_res = await session.execute(domain_stmt)
        dom_record = dom_res.scalar_one_or_none()
        if not dom_record:
            dom_record = Domain(
                domain=domain,
                punycode_domain=domain,
                unicode_domain=domain,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
            )
            session.add(dom_record)
            await session.commit()

        logger.info(f"Created scan {scan_uuid} for domain {domain}")
        return scan

    @staticmethod
    async def execute_mvp_scan(
        session: AsyncSession,
        scan_id: int,
    ) -> Scan:
        """Run Phase 1 MVP scan processing on a pending scan."""
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await session.execute(stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan with id {scan_id} not found")

        token_scan = scan_id_ctx.set(scan.scan_uuid)
        token_user = user_id_ctx.set(scan.user_id)

        try:
            scan.status = "in_progress"
            await session.commit()

            # MVP baseline heuristic (Phase 2 will plug in full asynchronous analyzers)
            scan.risk_score = 15.0
            scan.risk_level = "LOW"
            scan.confidence_score = 50.0
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)

            await session.commit()
            await session.refresh(scan)
            logger.info(f"Scan {scan.scan_uuid} completed successfully")
            return scan
        except Exception as exc:
            scan.status = "failed"
            await session.commit()
            logger.error(f"Scan {scan.scan_uuid} failed: {exc}", exc_info=True)
            raise
        finally:
            scan_id_ctx.reset(token_scan)
            user_id_ctx.reset(token_user)
