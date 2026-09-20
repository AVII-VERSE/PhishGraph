"""Health check API endpoints."""

from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field
from app.cache import get_cache
from app.config import get_settings
from app.db.session import check_db_health

router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(description="Overall service health status: 'ok' or 'degraded'")
    app: str = Field(description="Application name")
    version: str = Field(description="Application version")
    database: str = Field(description="Database connectivity status: 'connected' or 'disconnected'")
    cache: str = Field(description="Cache connectivity status: 'connected' or 'disconnected'")
    cache_backend: str = Field(description="Underlying cache type: 'redis' or 'memory'")
    timestamp: datetime = Field(description="UTC timestamp of health check")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    description="Inspects application status, database connectivity, and caching backend status.",
)
async def health_check(response: Response) -> dict[str, Any]:
    settings = get_settings()
    db_healthy = await check_db_health()

    cache_healthy = False
    cache_backend = "unknown"
    try:
        cache = await get_cache()
        cache_healthy = await cache.ping()
        cache_backend = cache.backend_type
    except Exception:
        cache_healthy = False

    is_ok = db_healthy and cache_healthy
    if not is_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if is_ok else "degraded",
        "app": settings.APP_NAME,
        "version": "0.1.0",
        "database": "connected" if db_healthy else "disconnected",
        "cache": "connected" if cache_healthy else "disconnected",
        "cache_backend": cache_backend,
        "timestamp": datetime.now(timezone.utc),
    }
