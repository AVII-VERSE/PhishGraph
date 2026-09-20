"""Pytest configuration and shared async fixtures."""

import os
from collections.abc import AsyncGenerator
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Force test environment variables before importing app components
os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["REDIS_URL"] = ""
os.environ["LOG_LEVEL"] = "DEBUG"

import app.db.session as db_session_module
from app.cache import InMemoryCache, _cache_instance, get_cache
from app.config import Settings, get_settings
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app
import app.db.models  # noqa: F401


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Provide testing settings."""
    return get_settings()


@pytest.fixture
async def test_engine():
    """Create a fresh in-memory SQLite database engine with StaticPool for each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Wire to db session module so handlers and services share the test db
    orig_engine = db_session_module._engine
    orig_factory = db_session_module._session_factory
    db_session_module._engine = engine
    db_session_module._session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    db_session_module._engine = orig_engine
    db_session_module._session_factory = orig_factory


@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated database session for testing."""
    session_factory = db_session_module.get_session_factory()
    async with session_factory() as session:
        yield session


@pytest.fixture
async def async_client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTPX AsyncClient wired to the test FastAPI app with DB overrides."""
    app = create_app()

    session_factory = db_session_module.get_session_factory()

    async def override_get_db_session() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
