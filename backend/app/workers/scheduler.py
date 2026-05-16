"""APScheduler integration for SentinelX background jobs."""
from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.services.kev_service import run_scheduled_kev_ingest
from app.services.news_service import run_scheduled_news_ingest
from app.services.nvd_service import run_scheduled_nvd_ingest

logger = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def start_scheduler() -> AsyncIOScheduler:
    scheduler = get_scheduler()
    if scheduler.running:
        return scheduler

    # CVE ingestion — polling mode, every 10 minutes. max_instances=1 keeps the
    # runs from stacking; the service also holds a process-wide boolean lock.
    scheduler.add_job(
        run_scheduled_nvd_ingest,
        trigger=IntervalTrigger(minutes=settings.nvd_ingest_interval_minutes),
        id="nvd_polling_ingest",
        name="NIST NVD polling ingest (lastMod)",
        coalesce=True,
        max_instances=1,
        replace_existing=True,
    )

    # CISA KEV sync — every 6 hours.
    scheduler.add_job(
        run_scheduled_kev_ingest,
        trigger=IntervalTrigger(hours=6),
        id="kev_sync",
        name="CISA KEV 6-hour sync",
        coalesce=True,
        max_instances=1,
        replace_existing=True,
    )

    # News feed ingest — every 10 minutes.
    scheduler.add_job(
        run_scheduled_news_ingest,
        trigger=IntervalTrigger(minutes=settings.news_ingest_interval_minutes),
        id="news_ingest",
        name="Cybersecurity news ingest",
        coalesce=True,
        max_instances=1,
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        "Scheduler started — NVD every %s min (polling), KEV every 6h, News every %s min",
        settings.nvd_ingest_interval_minutes,
        settings.news_ingest_interval_minutes,
    )
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler shut down")
    _scheduler = None
