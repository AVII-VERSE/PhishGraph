"""Watchlist and Risk Drift Monitoring Service."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models.user import User
from app.db.models.watch import Watch
from app.logging import get_logger
from app.services.scan_service import parse_and_validate_url

logger = get_logger("phishgraph.watch_service")


@dataclass
class DriftReport:
    """Detailed summary of infrastructure and risk drift between scan intervals."""

    domain: str
    url: str
    previous_risk: float
    current_risk: float
    score_delta: float
    has_meaningful_drift: bool = False
    changes: List[str] = field(default_factory=list)

    def format_alert_message(self) -> str:
        """Format Telegram notification message adhering to Section 16."""
        emoji = "🚨" if self.current_risk >= 70 else "⚠️"
        lines = [
            f"{emoji} *THREAT STATUS CHANGED*\n",
            f"*Domain:* `{self.domain}`",
            f"*Previous risk:* {int(self.previous_risk)}/100",
            f"*Current risk:* {int(self.current_risk)}/100",
            "",
            "*Changes observed:*",
        ]
        for ch in self.changes:
            lines.append(f"• {ch}")
        lines.append("")
        lines.append("_Automated risk-drift notification from PhishGraph Watchlist._")
        return "\n".join(lines)


class WatchService:
    """Manages active URL watches and detects infrastructure/risk drift."""

    @staticmethod
    async def add_watch(
        session: AsyncSession,
        user_id: int,
        raw_url: str,
        interval_hours: int = 12,
    ) -> Watch:
        """Add or reactivate a monitored URL for a user."""
        normalized_url, domain = parse_and_validate_url(raw_url)

        stmt = select(Watch).where(
            Watch.user_id == user_id,
            Watch.domain == domain,
        )
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if existing and existing.active:
            existing.interval_hours = interval_hours
            existing.url = normalized_url
            existing.next_scan_at = now + timedelta(hours=interval_hours)
            await session.commit()
            await session.refresh(existing)
            logger.info("Updated active watch on %s for user %s", domain, user_id)
            return existing

        # Enforce watchlist quota per user (Section 39)
        settings = get_settings()
        count_stmt = select(func.count(Watch.id)).where(
            Watch.user_id == user_id,
            Watch.active.is_(True),
        )
        active_count = (await session.execute(count_stmt)).scalar() or 0
        if active_count >= settings.MAX_WATCHLIST_ENTRIES_PER_USER:
            raise ValueError(
                f"Watchlist quota exceeded (maximum {settings.MAX_WATCHLIST_ENTRIES_PER_USER} entries allowed)."
            )

        if existing:
            existing.active = True
            existing.interval_hours = interval_hours
            existing.url = normalized_url
            existing.next_scan_at = now + timedelta(hours=interval_hours)
            await session.commit()
            await session.refresh(existing)
            logger.info("Reactivated existing watch on %s for user %s", domain, user_id)
            return existing

        watch = Watch(
            user_id=user_id,
            url=normalized_url,
            domain=domain,
            active=True,
            interval_hours=interval_hours,
            next_scan_at=now + timedelta(hours=interval_hours),
            created_at=now,
        )
        session.add(watch)
        await session.commit()
        await session.refresh(watch)
        logger.info("Created new watch on %s for user %s", domain, user_id)
        return watch

    @staticmethod
    async def remove_watch(
        session: AsyncSession,
        user_id: int,
        target: str,
    ) -> bool:
        """Deactivate an existing watch by URL or domain."""
        target_clean = target.strip().lower()
        if "://" in target_clean:
            _, domain = parse_and_validate_url(target_clean)
        else:
            domain = target_clean

        stmt = select(Watch).where(
            Watch.user_id == user_id,
            Watch.domain == domain,
            Watch.active == True,
        )
        res = await session.execute(stmt)
        watch = res.scalar_one_or_none()
        if not watch:
            return False

        watch.active = False
        await session.commit()
        logger.info("Deactivated watch on %s for user %s", domain, user_id)
        return True

    @staticmethod
    async def get_user_watchlist(
        session: AsyncSession,
        telegram_user_id: int,
    ) -> List[Watch]:
        """Fetch all active watches for a Telegram user."""
        u_stmt = select(User).where(User.telegram_user_id == telegram_user_id)
        user = (await session.execute(u_stmt)).scalar_one_or_none()
        if not user:
            return []

        stmt = (
            select(Watch)
            .where(Watch.user_id == user.id, Watch.active == True)
            .order_by(Watch.id.desc())
        )
        res = await session.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    def evaluate_drift(
        previous_details: Dict[str, Any],
        current_details: Dict[str, Any],
    ) -> DriftReport:
        """Compare two scan snapshots and identify meaningful security drift."""
        prev_scan = previous_details.get("scan", {})
        curr_scan = current_details.get("scan", {})

        domain = curr_scan.get("domain") or prev_scan.get("domain") or "unknown"
        url = curr_scan.get("original_url") or prev_scan.get("original_url") or ""

        prev_score = float(prev_scan.get("risk_score") or 0)
        curr_score = float(curr_scan.get("risk_score") or 0)
        delta = curr_score - prev_score

        changes: List[str] = []

        # 1. Significant score difference
        if abs(delta) >= 10:
            direction = "increased" if delta > 0 else "decreased"
            changes.append(f"Risk score {direction} from {int(prev_score)} to {int(curr_score)} ({'+' if delta > 0 else ''}{int(delta)})")

        # 2. Threat feed changes
        prev_ti_hits = {
            ti.get("provider"): ti.get("provider_status")
            for ti in previous_details.get("threat_intel", [])
            if ti.get("provider_status") in ("malicious", "suspicious")
        }
        curr_ti_hits = {
            ti.get("provider"): ti.get("provider_status")
            for ti in current_details.get("threat_intel", [])
            if ti.get("provider_status") in ("malicious", "suspicious")
        }

        new_ti = set(curr_ti_hits.keys()) - set(prev_ti_hits.keys())
        if new_ti:
            changes.append(f"Threat feed match added ({', '.join(sorted(new_ti))})")

        # 3. IP address resolution changes
        prev_ips = {r.get("value") for r in previous_details.get("dns_records", []) if r.get("record_type") in ("A", "AAAA")}
        curr_ips = {r.get("value") for r in current_details.get("dns_records", []) if r.get("record_type") in ("A", "AAAA")}

        if prev_ips and curr_ips and prev_ips != curr_ips:
            changes.append("Resolved IP address(es) changed")

        # 4. Correlation increases
        prev_corr_count = len(previous_details.get("correlations", []))
        curr_corr_count = len(current_details.get("correlations", []))
        if curr_corr_count > prev_corr_count:
            diff_corr = curr_corr_count - prev_corr_count
            changes.append(f"{diff_corr} additional suspicious-domain correlation(s) found")

        has_drift = len(changes) > 0

        return DriftReport(
            domain=domain,
            url=url,
            previous_risk=prev_score,
            current_risk=curr_score,
            score_delta=delta,
            has_meaningful_drift=has_drift,
            changes=changes,
        )
