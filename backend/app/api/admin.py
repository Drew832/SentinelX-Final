"""Admin endpoints for triggering ingestion jobs."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.models.ingestion_log import IngestionLog
from app.services.kev_service import ingest_kev
from app.services.news_service import ingest_news
from app.services.nvd_service import ingest_nvd_window, ingest_recent_nvd
from app.services.risk_scoring import rescore_all_profiles

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/ingest/nvd")
async def trigger_nvd(
    minutes: int | None = None,
    days: int | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, int | str]:
    """Manually trigger an NVD ingest.

    Provide `?days=N` for day-scale backfills or `?minutes=N` for the short
    window that APScheduler used to run. Defaults to 10 minutes.
    """
    from datetime import datetime, timedelta, timezone

    end = datetime.now(tz=timezone.utc)
    if days is not None:
        start = end - timedelta(days=days)
        run = await ingest_nvd_window(db, start, end, source="nvd.manual")
        return {
            "total_fetched": run.total_fetched,
            "inserted": run.inserted,
            "updated": run.updated,
            "failed": run.failed,
            "window_days": days,
        }
    window_minutes = minutes or 10
    inserted, updated = await ingest_recent_nvd(db, minutes=window_minutes)
    return {
        "inserted": inserted,
        "updated": updated,
        "window_minutes": window_minutes,
    }


@router.post("/ingest/kev")
async def trigger_kev(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, int]:
    matched, total = await ingest_kev(db)
    return {"matched_existing_cves": matched, "kev_entries": total}


@router.post("/ingest/news")
async def trigger_news(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, int]:
    inserted, retained = await ingest_news(db)
    return {"inserted": inserted, "retained": retained}


@router.post("/profiles/rescore")
async def trigger_rescore(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, int]:
    count = await rescore_all_profiles(db)
    return {"profiles_rescored": count}


@router.get("/status")
async def system_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, object]:
    from sqlalchemy import func, select
    from app.models.cve import CVE
    from app.models.news import NewsArticle
    from app.models.profile import OrgProfile
    from app.models.user import User as UserModel

    cves = (await db.execute(select(func.count(CVE.cve_id)))).scalar_one()
    kev = (await db.execute(select(func.count(CVE.cve_id)).where(CVE.is_kev.is_(True)))).scalar_one()
    news = (await db.execute(select(func.count(NewsArticle.id)))).scalar_one()
    profiles = (await db.execute(select(func.count(OrgProfile.id)))).scalar_one()
    users = (await db.execute(select(func.count(UserModel.id)))).scalar_one()

    return {
        "cves": cves,
        "kev": kev,
        "news_articles": news,
        "org_profiles": profiles,
        "users": users,
    }


@router.get("/ingestion/logs")
async def ingestion_logs(
    limit: int = 50,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[dict]:
    from sqlalchemy import select

    stmt = select(IngestionLog).order_by(IngestionLog.started_at.desc()).limit(limit)
    if source:
        stmt = stmt.where(IngestionLog.source == source)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "source": r.source,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "duration_seconds": r.duration_seconds,
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "window_end": r.window_end.isoformat() if r.window_end else None,
            "total_fetched": r.total_fetched,
            "inserted": r.inserted,
            "updated": r.updated,
            "failed": r.failed,
            "error_message": r.error_message,
        }
        for r in rows
    ]
