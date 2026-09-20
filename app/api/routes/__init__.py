"""API Routes package."""

from fastapi import APIRouter
from app.api.routes.health import router as health_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health_router, tags=["Health"])

__all__ = ["api_v1_router", "health_router"]
