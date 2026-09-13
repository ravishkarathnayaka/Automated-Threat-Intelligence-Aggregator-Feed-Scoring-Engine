"""Database connection and session lifecycle management using SQLAlchemy 2.0 async engine."""

import os
from typing import Any, AsyncGenerator, Dict

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cti_core.models.indicator import Base

# Default to local SQLite for $0 standalone setup; override with PostgreSQL via DATABASE_URL in docker
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cti_engine.db")

# Normalize DB URL for async drivers
if RAW_DATABASE_URL.startswith("sqlite:///"):
    ASYNC_DATABASE_URL = RAW_DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///")
elif RAW_DATABASE_URL.startswith("postgresql://"):
    ASYNC_DATABASE_URL = RAW_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
elif RAW_DATABASE_URL.startswith("postgres://"):
    ASYNC_DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql+asyncpg://")
else:
    ASYNC_DATABASE_URL = RAW_DATABASE_URL

# Engine configuration
engine_kwargs: Dict[str, Any] = {"echo": False, "future": True}
if ASYNC_DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

async_engine = create_async_engine(ASYNC_DATABASE_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Create database tables if they do not already exist."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for obtaining an isolated async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
