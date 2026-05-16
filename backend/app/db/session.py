"""Async SQLAlchemy session management."""
from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


_engine_kwargs: dict = {"future": True, "echo": False}
if settings.database_url.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_async_engine(settings.database_url, **_engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


def _ensure_user_columns_sqlite(sync_conn) -> None:
    if sync_conn.dialect.name != "sqlite":
        return
    rows = sync_conn.execute(text("PRAGMA table_info(users)")).fetchall()
    cols = {r[1] for r in rows}
    if "otp_hashed" not in cols:
        sync_conn.execute(text("ALTER TABLE users ADD COLUMN otp_hashed VARCHAR(255)"))
    if "otp_expires_at" not in cols:
        sync_conn.execute(text("ALTER TABLE users ADD COLUMN otp_expires_at DATETIME"))
    if "otp_attempts" not in cols:
        sync_conn.execute(
            text("ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0 NOT NULL")
        )
    if "otp_last_sent_at" not in cols:
        sync_conn.execute(text("ALTER TABLE users ADD COLUMN otp_last_sent_at DATETIME"))


async def init_db() -> None:
    """Create tables if they do not exist and run lightweight column migrations."""
    from app.models import (  # noqa: F401  (register metadata)
        cve,
        ingestion_log,
        kev_entry,
        news,
        profile,
        user,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_profile_columns)
        await conn.run_sync(_ensure_user_columns_sqlite)


def _ensure_profile_columns(sync_conn) -> None:
    """Best-effort ALTER TABLE for columns added after an initial install.

    Alembic would be cleaner, but for a single-table evolution the cost of
    introspecting the live schema and issuing conditional ALTERs is minimal
    and keeps this a zero-setup upgrade.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(sync_conn)
    if "org_profiles" not in inspector.get_table_names():
        return

    existing = {c["name"] for c in inspector.get_columns("org_profiles")}
    statements: list[str] = []
    if "asset_name" not in existing:
        statements.append("ALTER TABLE org_profiles ADD COLUMN asset_name VARCHAR(128)")
    if "environment" not in existing:
        statements.append(
            "ALTER TABLE org_profiles ADD COLUMN environment VARCHAR(16) DEFAULT 'PROD' NOT NULL"
        )
    if "internet_exposed" not in existing:
        statements.append(
            "ALTER TABLE org_profiles ADD COLUMN internet_exposed BOOLEAN DEFAULT 0 NOT NULL"
        )
    if "business_criticality" not in existing:
        statements.append(
            "ALTER TABLE org_profiles ADD COLUMN business_criticality INTEGER DEFAULT 3 NOT NULL"
        )
    for stmt in statements:
        sync_conn.execute(text(stmt))
