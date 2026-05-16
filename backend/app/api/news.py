"""Cybersecurity News Feed API."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.news import NewsArticle
from app.schemas.news import NewsArticleOut, NewsListResponse
from app.services.news_service import ingest_news, list_news

router = APIRouter(prefix="/news", tags=["news"])


@router.get("", response_model=NewsListResponse)
async def get_news(
    db: AsyncSession = Depends(get_db),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=300),
) -> NewsListResponse:
    articles = list(await list_news(db, category=category, search=search, limit=limit))
    total = (await db.execute(select(func.count(NewsArticle.id)))).scalar_one()
    last = (await db.execute(select(func.max(NewsArticle.fetched_at)))).scalar_one_or_none()

    cat_rows = await db.execute(
        select(NewsArticle.category, func.count(NewsArticle.id)).group_by(NewsArticle.category)
    )
    counts: dict[str, int] = {}
    for cat, count in cat_rows.all():
        counts[cat] = count

    return NewsListResponse(
        total=total,
        categories=sorted(counts.keys()),
        counts_by_category=counts,
        items=[NewsArticleOut.model_validate(a) for a in articles],
        last_refresh=last,
    )


@router.post("/refresh", response_model=NewsListResponse)
async def refresh_news(db: AsyncSession = Depends(get_db)) -> NewsListResponse:
    await ingest_news(db)
    return await get_news(db)  # type: ignore[return-value]
