"""Schemas for cybersecurity news feed."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class NewsArticleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    url: str
    source: str
    category: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    published_at: datetime
    fetched_at: datetime


class NewsListResponse(BaseModel):
    total: int
    categories: List[str]
    counts_by_category: dict[str, int]
    items: List[NewsArticleOut]
    last_refresh: Optional[datetime] = None
