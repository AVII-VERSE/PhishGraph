"""Unit tests for operational metrics service."""

import pytest
from app.services.metrics_service import MetricsService


def test_metrics_counters_and_uptime():
    """Verify runtime counters increment properly."""
    initial_uptime = MetricsService.get_uptime_seconds()
    assert initial_uptime >= 0.0

    MetricsService.record_scan_executed(risk_score=25.0)
    MetricsService.record_scan_executed(risk_score=85.0)  # High risk
    MetricsService.record_cache_hit()
    MetricsService.record_threat_query()
    MetricsService.record_rate_limit_hit()

    summary = {
        "uptime_seconds": 120.5,
        "runtime": {
            "scans_executed_session": 2,
            "high_risk_scans_session": 1,
            "cached_lookups_session": 1,
            "threat_queries_session": 1,
            "rate_limit_hits_session": 1,
        },
        "database": {
            "total_scans": 42,
            "high_risk_scans": 7,
            "active_watches": 3,
        },
    }

    prom_text = MetricsService.format_prometheus_metrics(summary)
    assert "phishgraph_uptime_seconds 120.5" in prom_text
    assert "phishgraph_scans_total 42" in prom_text
    assert "phishgraph_high_risk_scans_total 7" in prom_text
    assert "phishgraph_active_watches 3" in prom_text
    assert "phishgraph_rate_limit_hits_total 1" in prom_text
