"""Unit tests for scan service and URL extraction."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.scan_service import (
    ScanService,
    extract_urls_from_text,
    generate_scan_id,
    parse_and_validate_url,
)


def test_extract_urls_from_text():
    """Verify URL detection inside text and messages."""
    text = "Check this suspicious link https://paypa1-login.example/verify and http://tracker.test/now"
    urls = extract_urls_from_text(text)
    assert len(urls) == 2
    assert urls[0] == "https://paypa1-login.example/verify"
    assert urls[1] == "http://tracker.test/now"

    empty_text = "No links here at all."
    assert extract_urls_from_text(empty_text) == []


def test_parse_and_validate_url():
    """Verify URL normalization and domain extraction."""
    url, domain = parse_and_validate_url("https://sub.evil-bank.example:8443/login?user=admin")
    assert url == "https://sub.evil-bank.example:8443/login?user=admin"
    assert domain == "sub.evil-bank.example"

    # URL without scheme defaults to https
    url2, domain2 = parse_and_validate_url("phishing-site.test/account")
    assert url2 == "https://phishing-site.test/account"
    assert domain2 == "phishing-site.test"

    # Invalid URL
    with pytest.raises(ValueError):
        parse_and_validate_url("not a domain at all")


def test_generate_scan_id():
    """Verify format of generated scan IDs."""
    scan_id = generate_scan_id()
    assert scan_id.startswith("SCAN-")
    parts = scan_id.split("-")
    assert len(parts) == 3
    assert len(parts[1]) == 4  # Year


@pytest.mark.asyncio
async def test_get_or_create_user(db_session: AsyncSession):
    """Verify user registration and update in scan service."""
    user = await ScanService.get_or_create_user(
        session=db_session,
        telegram_user_id=111222,
        username="test_user",
        first_name="Test",
    )
    assert user.id is not None
    assert user.telegram_user_id == 111222

    # Call again with updated username
    user_updated = await ScanService.get_or_create_user(
        session=db_session,
        telegram_user_id=111222,
        username="updated_user",
    )
    assert user_updated.id == user.id
    assert user_updated.username == "updated_user"


@pytest.mark.asyncio
async def test_create_and_execute_scan(db_session: AsyncSession):
    """Verify full scan creation and execution workflow."""
    user = await ScanService.get_or_create_user(
        session=db_session,
        telegram_user_id=333444,
        username="investigator",
    )

    scan = await ScanService.create_scan(
        session=db_session,
        raw_url="https://paypa1-update.test/login",
        user_id=user.id,
    )
    assert scan.id is not None
    assert scan.domain == "paypa1-update.test"
    assert scan.status == "pending"

    # Execute scan with allow_private_in_testing for mock domain
    completed_scan, heuristics, dns_res, rdap_res, tls_res, redir_res = (
        await ScanService.execute_scan(
            session=db_session,
            scan_id=scan.id,
            allow_private_in_testing=True,
        )
    )
    assert completed_scan.status == "completed"
    assert completed_scan.risk_score is not None
    assert completed_scan.confidence_score is not None
    assert completed_scan.completed_at is not None
    assert heuristics is not None
    assert heuristics.hostname == "paypa1-update.test"
