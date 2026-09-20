"""Unit tests for WatchService and Risk Drift Detection."""

from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.user import User
from app.services.watch_service import WatchService


@pytest.mark.asyncio
async def test_watch_service_crud(db_session: AsyncSession):
    """Verify adding, reactivating, listing, and removing URL watches."""
    user = User(
        telegram_user_id=777111,
        username="hunter_bob",
        first_name="Bob",
        created_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # 1. Add watch
    watch = await WatchService.add_watch(
        session=db_session,
        user_id=user.id,
        raw_url="https://suspicious-portal.test/login",
        interval_hours=6,
    )
    assert watch.id is not None
    assert watch.domain == "suspicious-portal.test"
    assert watch.active is True
    assert watch.interval_hours == 6

    # 2. Get user watchlist
    watchlist = await WatchService.get_user_watchlist(db_session, telegram_user_id=777111)
    assert len(watchlist) == 1
    assert watchlist[0].domain == "suspicious-portal.test"

    # 3. Remove watch
    removed = await WatchService.remove_watch(db_session, user_id=user.id, target="suspicious-portal.test")
    assert removed is True

    # 4. Confirm watchlist is now empty
    watchlist_after = await WatchService.get_user_watchlist(db_session, telegram_user_id=777111)
    assert len(watchlist_after) == 0

    # 5. Reactivate watch
    watch_reactivated = await WatchService.add_watch(
        session=db_session,
        user_id=user.id,
        raw_url="https://suspicious-portal.test/login",
        interval_hours=24,
    )
    assert watch_reactivated.id == watch.id
    assert watch_reactivated.active is True
    assert watch_reactivated.interval_hours == 24


def test_evaluate_drift_detection():
    """Verify evaluation of risk drift, new threat feeds, and IP shifts."""
    prev_snapshot = {
        "scan": {
            "domain": "stealth-phish.test",
            "original_url": "https://stealth-phish.test",
            "risk_score": 34.0,
        },
        "dns_records": [
            {"record_type": "A", "value": "192.0.2.1"}
        ],
        "threat_intel": [],
        "correlations": [],
    }

    curr_snapshot = {
        "scan": {
            "domain": "stealth-phish.test",
            "original_url": "https://stealth-phish.test",
            "risk_score": 77.0,
        },
        "dns_records": [
            {"record_type": "A", "value": "198.51.100.5"}  # IP changed
        ],
        "threat_intel": [
            {"provider": "virustotal", "provider_status": "malicious"}  # Threat hit added
        ],
        "correlations": [
            {"target_scan_id": 10},
            {"target_scan_id": 11},  # 2 correlations added
        ],
    }

    drift = WatchService.evaluate_drift(prev_snapshot, curr_snapshot)

    assert drift.has_meaningful_drift is True
    assert drift.domain == "stealth-phish.test"
    assert drift.previous_risk == 34.0
    assert drift.current_risk == 77.0
    assert drift.score_delta == 43.0

    assert any("Threat feed match added" in ch for ch in drift.changes)
    assert any("Resolved IP address(es) changed" in ch for ch in drift.changes)
    assert any("2 additional suspicious-domain correlation(s) found" in ch for ch in drift.changes)

    # Verify alert message format conforms to Section 16
    msg = drift.format_alert_message()
    assert "THREAT STATUS CHANGED" in msg
    assert "*Domain:* `stealth-phish.test`" in msg
    assert "*Previous risk:* 34/100" in msg
    assert "*Current risk:* 77/100" in msg
