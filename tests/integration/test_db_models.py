"""Integration tests for database models and session persistence."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.domain import Domain
from app.db.models.scan import Scan
from app.db.models.user import User


@pytest.mark.asyncio
async def test_user_persistence(db_session: AsyncSession):
    """Verify persisting and querying User records."""
    user = User(
        telegram_user_id=123456789,
        username="sec_analyst",
        first_name="Alice",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    assert user.id is not None
    assert user.is_blocked is False

    # Query back
    stmt = select(User).where(User.telegram_user_id == 123456789)
    result = await db_session.execute(stmt)
    persisted_user = result.scalar_one_or_none()

    assert persisted_user is not None
    assert persisted_user.username == "sec_analyst"


@pytest.mark.asyncio
async def test_scan_and_relationship_persistence(db_session: AsyncSession):
    """Verify creating a scan linked to a user."""
    user = User(
        telegram_user_id=987654321,
        username="threat_hunter",
        first_name="Bob",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    scan = Scan(
        user_id=user.id,
        original_url="https://paypa1-secure-login.example/verify",
        normalized_url="https://paypa1-secure-login.example/verify",
        domain="paypa1-secure-login.example",
        status="completed",
        risk_score=85.0,
        risk_level="CRITICAL",
        confidence_score=78.0,
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    assert scan.id is not None
    assert scan.scan_uuid.startswith("SCAN-")
    assert scan.user_id == user.id

    # Verify query by domain
    stmt = select(Scan).where(Scan.domain == "paypa1-secure-login.example")
    result = await db_session.execute(stmt)
    retrieved_scan = result.scalar_one_or_none()

    assert retrieved_scan is not None
    assert retrieved_scan.risk_score == 85.0
    assert retrieved_scan.risk_level == "CRITICAL"


@pytest.mark.asyncio
async def test_domain_persistence(db_session: AsyncSession):
    """Verify creating and retrieving Domain records."""
    domain_rec = Domain(
        domain="suspicious.example",
        punycode_domain="suspicious.example",
        unicode_domain="suspicious.example",
        registrar="Example Registrar Inc",
    )
    db_session.add(domain_rec)
    await db_session.commit()
    await db_session.refresh(domain_rec)

    assert domain_rec.id is not None

    stmt = select(Domain).where(Domain.domain == "suspicious.example")
    result = await db_session.execute(stmt)
    persisted = result.scalar_one_or_none()

    assert persisted is not None
    assert persisted.registrar == "Example Registrar Inc"
