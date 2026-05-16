"""SentinelX FastAPI application entrypoint."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.router import api_router
from app.core.config import settings
from app.core.security import hash_password
from app.db.session import SessionLocal, init_db
from app.models.user import User, UserRole
from app.services.kev_service import sync_kev
from app.services.news_service import run_scheduled_news_ingest
from app.services.nvd_service import run_initial_nvd_ingest
from app.workers.scheduler import shutdown_scheduler, start_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx")


async def _seed_default_users() -> None:
    """Create the bootstrap admin if no users exist."""
    if not settings.initial_admin_email or not settings.initial_admin_password:
        return
    async with SessionLocal() as db:
        existing = await db.execute(
            select(User).where(User.email == settings.initial_admin_email)
        )
        if existing.scalar_one_or_none():
            return
        admin = User(
            email=settings.initial_admin_email,
            username=settings.initial_admin_username,
            hashed_password=hash_password(settings.initial_admin_password),
            role=UserRole.ADMIN,
            is_active=True,
            otp_hashed=None,
            otp_expires_at=None,
        )
        db.add(admin)
        await db.commit()
        logger.info("Bootstrapped initial admin: %s", admin.email)


async def _initial_ingest() -> None:
    """Seed the DB with the last 30 days of published CVEs on first boot.

    Never raises — errors are logged so the app still comes up cleanly. When
    the seed actually runs (i.e. the DB was empty), follow it with a second
    KEV sync so freshly-inserted CVEs get their `is_kev` flags set without
    waiting for the 6-hour scheduler tick.
    """
    try:
        seeded = await run_initial_nvd_ingest()
        if seeded:
            try:
                await sync_kev()
            except Exception:  # noqa: BLE001
                logger.warning("Post-seed KEV resync failed (non-fatal)")
    except Exception:  # noqa: BLE001
        logger.exception("Initial CVE ingest task failed (non-fatal)")


async def _initial_kev_sync() -> None:
    """Trigger a KEV sync on boot, non-blocking and crash-safe."""
    try:
        await sync_kev()
    except Exception:  # noqa: BLE001
        logger.warning("Initial KEV sync failed (non-fatal)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Create tables.
    await init_db()
    # 2. Seed default users.
    await _seed_default_users()
    # 3. Start the scheduler.
    start_scheduler()
    # 4 & 5. Kick off background seeds — never block startup.
    asyncio.create_task(_initial_ingest())
    asyncio.create_task(_initial_kev_sync())
    # News can also seed in the background so the feed is warm immediately.
    asyncio.create_task(run_scheduled_news_ingest())
    try:
        yield
    finally:
        shutdown_scheduler()


app = FastAPI(
    title=settings.app_name,
    description="SentinelX — Vulnerability Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "app": settings.app_name}


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
