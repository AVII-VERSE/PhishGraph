"""Metrics route exposing operational and database statistics."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, Header, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db_session
from app.services.metrics_service import MetricsService

router = APIRouter()


@router.get(
    "/metrics",
    summary="System and Operational Metrics",
    description="Returns JSON or Prometheus-formatted metrics depending on the Accept header.",
)
async def get_metrics(
    session: AsyncSession = Depends(get_db_session),
    accept: str = Header(default="application/json"),
) -> Any:
    summary = await MetricsService.get_metrics_summary(session)

    if "text/plain" in accept:
        prom_text = MetricsService.format_prometheus_metrics(summary)
        return Response(
            content=prom_text,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return summary
