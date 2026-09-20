"""Operational metrics collection and reporting service for PhishGraph."""

import time
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.correlation import Correlation
from app.db.models.scan import Scan
from app.db.models.user import User
from app.db.models.watch import Watch


class MetricsService:
    """Collects application performance counters and database inventory metrics."""

    _start_time: float = time.time()
    _scans_executed_counter: int = 0
    _high_risk_scans_counter: int = 0
    _cached_lookups_counter: int = 0
    _threat_intel_queries_counter: int = 0
    _rate_limit_hits_counter: int = 0

    @classmethod
    def record_scan_executed(cls, risk_score: float) -> None:
        """Increment scan execution counter and conditionally high risk counter."""
        cls._scans_executed_counter += 1
        if risk_score >= 70.0:
            cls._high_risk_scans_counter += 1

    @classmethod
    def record_cache_hit(cls) -> None:
        """Increment cached lookup counter."""
        cls._cached_lookups_counter += 1

    @classmethod
    def record_threat_query(cls) -> None:
        """Increment threat intelligence API query counter."""
        cls._threat_intel_queries_counter += 1

    @classmethod
    def record_rate_limit_hit(cls) -> None:
        """Increment rate limit violation counter."""
        cls._rate_limit_hits_counter += 1

    @classmethod
    def get_uptime_seconds(cls) -> float:
        """Calculate elapsed uptime since application startup."""
        return max(0.0, time.time() - cls._start_time)

    @classmethod
    async def get_metrics_summary(cls, session: AsyncSession) -> Dict[str, Any]:
        """Aggregate in-memory runtime counters and persistent database counts."""
        # Query persistent DB counts
        total_scans = (await session.execute(select(func.count(Scan.id)))).scalar() or 0
        high_risk_scans = (
            await session.execute(
                select(func.count(Scan.id)).where(Scan.risk_score >= 70.0)
            )
        ).scalar() or 0
        total_users = (await session.execute(select(func.count(User.id)))).scalar() or 0
        active_watches = (
            await session.execute(
                select(func.count(Watch.id)).where(Watch.active.is_(True))
            )
        ).scalar() or 0
        correlations_count = (
            await session.execute(select(func.count(Correlation.id)))
        ).scalar() or 0

        return {
            "uptime_seconds": round(cls.get_uptime_seconds(), 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "runtime": {
                "scans_executed_session": cls._scans_executed_counter,
                "high_risk_scans_session": cls._high_risk_scans_counter,
                "cached_lookups_session": cls._cached_lookups_counter,
                "threat_queries_session": cls._threat_intel_queries_counter,
                "rate_limit_hits_session": cls._rate_limit_hits_counter,
            },
            "database": {
                "total_scans": total_scans,
                "high_risk_scans": high_risk_scans,
                "total_users": total_users,
                "active_watches": active_watches,
                "total_correlations": correlations_count,
            },
        }

    @classmethod
    def format_prometheus_metrics(cls, summary: Dict[str, Any]) -> str:
        """Format metrics dictionary into standard Prometheus plain-text format."""
        runtime = summary.get("runtime", {})
        db = summary.get("database", {})
        lines = [
            "# HELP phishgraph_uptime_seconds Application uptime in seconds",
            "# TYPE phishgraph_uptime_seconds gauge",
            f"phishgraph_uptime_seconds {summary.get('uptime_seconds', 0.0)}",
            "",
            "# HELP phishgraph_scans_total Total lifetime scans recorded in database",
            "# TYPE phishgraph_scans_total counter",
            f"phishgraph_scans_total {db.get('total_scans', 0)}",
            "",
            "# HELP phishgraph_high_risk_scans_total Total high-risk scans (score >= 70)",
            "# TYPE phishgraph_high_risk_scans_total counter",
            f"phishgraph_high_risk_scans_total {db.get('high_risk_scans', 0)}",
            "",
            "# HELP phishgraph_active_watches Total currently monitored watchlist entries",
            "# TYPE phishgraph_active_watches gauge",
            f"phishgraph_active_watches {db.get('active_watches', 0)}",
            "",
            "# HELP phishgraph_rate_limit_hits_total Total rate limit enforcement blocks",
            "# TYPE phishgraph_rate_limit_hits_total counter",
            f"phishgraph_rate_limit_hits_total {runtime.get('rate_limit_hits_session', 0)}",
            "",
            "# HELP phishgraph_cached_lookups_total Cached intelligence lookups served",
            "# TYPE phishgraph_cached_lookups_total counter",
            f"phishgraph_cached_lookups_total {runtime.get('cached_lookups_session', 0)}",
            "",
        ]
        return "\n".join(lines)
