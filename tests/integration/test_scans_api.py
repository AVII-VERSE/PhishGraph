"""Integration tests for Scans API endpoints (JSON, HTML, PDF)."""

from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from app.db.models.scan import Scan
from app.main import app


@pytest.mark.asyncio
async def test_get_scan_details_endpoint(test_engine, db_session):
    """Verify GET /api/v1/scans/{scan_uuid} returns complete scan details JSON."""
    scan = Scan(
        scan_uuid="SCAN-2026-API001",
        original_url="https://fake-bank-portal.test/login",
        normalized_url="https://fake-bank-portal.test/login",
        domain="fake-bank-portal.test",
        status="completed",
        risk_score=95.0,
        risk_level="CRITICAL",
        confidence_score=90.0,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Successful JSON lookup
        res = await client.get("/api/v1/scans/SCAN-2026-API001")
        assert res.status_code == 200
        data = res.json()
        assert data["scan"]["scan_uuid"] == "SCAN-2026-API001"
        assert data["scan"]["domain"] == "fake-bank-portal.test"
        assert data["scan"]["risk_level"] == "CRITICAL"

        # 2. HTML Report endpoint
        html_res = await client.get("/api/v1/scans/SCAN-2026-API001/report")
        assert html_res.status_code == 200
        assert "text/html" in html_res.headers["content-type"]
        assert "SCAN-2026-API001" in html_res.text
        assert "CRITICAL RISK" in html_res.text

        # 3. PDF Download endpoint
        pdf_res = await client.get("/api/v1/scans/SCAN-2026-API001/pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF")

        # 4. Unknown scan returns 404
        missing_res = await client.get("/api/v1/scans/SCAN-2026-NOTFOUND")
        assert missing_res.status_code == 404
