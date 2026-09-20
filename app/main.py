"""PhishGraph FastAPI main application entrypoint."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from app.api.routes import api_v1_router
from app.api.routes.health import router as root_health_router
from app.cache import get_cache
from app.config import get_settings
from app.db.session import close_db, init_db
from app.logging import get_logger, setup_logging

logger = get_logger("phishgraph.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan managing startup and graceful shutdown."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info(f"Starting {settings.APP_NAME} in [{settings.APP_ENV}] mode")

    # If SQLite is used in development/testing, ensure tables are present
    if settings.is_sqlite:
        await init_db()

    # Initialize cache backend
    await get_cache()

    yield

    logger.info(f"Shutting down {settings.APP_NAME}")
    cache = await get_cache()
    await cache.close()
    await close_db()


def create_app() -> FastAPI:
    """Factory function for FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="PhishGraph API",
        description="Defensive Cybersecurity Phishing Infrastructure & Campaign Intelligence API",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Global Exception Handler protecting against traceback leakage
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled error processing {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "message": "An unexpected error occurred during processing. Please try again later.",
            },
        )

    # Mount health router at root /health for simple container healthchecks
    app.include_router(root_health_router, tags=["Health"])

    # Mount API v1 router
    app.include_router(api_v1_router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
