"""API Routes package."""

from fastapi import APIRouter
from app.api.routes.health import router as health_router
from app.api.routes.scans import router as scans_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health_router, tags=["Health"])
api_v1_router.include_router(scans_router)

__all__ = ["api_v1_router", "health_router", "scans_router"]

