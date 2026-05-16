"""Cybersecurity news ingestion from NewsAPI and RSS feeds."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.news import NewsArticle

logger = logging.getLogger(__name__)

NEWSAPI_URL = "https://newsapi.org/v2/everything"
NEWSAPI_QUERY = '(cybersecurity OR vulnerability OR ransomware OR "data breach" OR malware OR exploit OR "zero-day")'

CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("Vulnerabilities", ("cve-", "vulnerability", "vulnerabilities", "zero-day", "0-day", "patch", "flaw", "rce", "sql injection", "xss")),
    ("Malware / Ransomware", ("malware", "ransomware", "trojan", "worm", "spyware", "rootkit", "stealer", "botnet", "loader")),
    ("Breach / Incident", ("breach", "leak", "leaked", "hacked", "compromised", "stolen", "incident", "exposed", "data theft")),
    ("Threat Intel", ("threat actor", "apt", "nation-state", "campaign", "attribution", "ioc", "indicators of compromise", "ttp", "phishing")),
]


def _hash_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:24]


def categorize(title: str, description: str | None) -> str:
    haystack = f"{title} {description or ''}".lower()
    for label, keywords in CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in haystack:
                return label
    return "General Security"


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _clean_html(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = re.sub(r"<[^>]+>", "", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or None


def _domain_source(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        host = host.removeprefix("www.")
        mapping = {
            "thehackernews.com": "The Hacker News",
            "feeds.feedburner.com": "The Hacker News",
            "bleepingcomputer.com": "BleepingComputer",
            "krebsonsecurity.com": "Krebs on Security",
            "darkreading.com": "Dark Reading",
        }
        for needle, label in mapping.items():
            if needle in host:
                return label
        return host or "Unknown"
    except Exception:  # noqa: BLE001
        return "Unknown"


async def _fetch_newsapi(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    if not settings.newsapi_key:
        return []
    # Pull anything from the last `news_retention_hours` so we always have
    # enough headlines on the wall even if the feed has been quiet.
    from_dt = (
        datetime.now(tz=timezone.utc) - timedelta(hours=settings.news_retention_hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "q": NEWSAPI_QUERY,
        "language": "en",
        "sortBy": "publishedAt",
        "pageSize": 100,
        "from": from_dt,
        "apiKey": settings.newsapi_key,
    }
    try:
        resp = await client.get(NEWSAPI_URL, params=params, timeout=30)
        if resp.status_code == 429:
            logger.warning("NewsAPI rate limited")
            return []
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("NewsAPI fetch failed: %s", exc)
        return []

    data = resp.json()
    articles: list[dict[str, Any]] = []
    for item in data.get("articles", []):
        url = item.get("url")
        title = item.get("title")
        if not url or not title or title == "[Removed]":
            continue
        published = _parse_datetime(item.get("publishedAt"))
        if not published:
            continue
        source = (item.get("source") or {}).get("name") or _domain_source(url)
        description = _clean_html(item.get("description") or item.get("content"))
        articles.append(
            {
                "id": _hash_id("newsapi", url),
                "title": title.strip()[:512],
                "url": url,
                "source": source,
                "description": description,
                "image_url": item.get("urlToImage"),
                "published_at": published,
                "category": categorize(title, description),
            }
        )
    return articles


def _parse_feed_sync(url: str) -> list[dict[str, Any]]:
    try:
        import feedparser  # type: ignore
    except ImportError:  # pragma: no cover
        logger.warning("feedparser not available")
        return []

    parsed = feedparser.parse(url)
    results: list[dict[str, Any]] = []
    source_name = _domain_source(url)
    for entry in parsed.entries[:40]:
        link = entry.get("link")
        title = entry.get("title")
        if not link or not title:
            continue
        published = (
            _parse_datetime(entry.get("published"))
            or _parse_datetime(entry.get("updated"))
        )
        if not published:
            # Some feeds omit dates intermittently; treat as "now" so the
            # article still surfaces in the dashboard rather than being
            # silently dropped.
            published = datetime.now(tz=timezone.utc)
        description = _clean_html(entry.get("summary") or entry.get("description"))
        image_url = None
        media = entry.get("media_content") or []
        if isinstance(media, list) and media:
            image_url = media[0].get("url")
        enclosures = entry.get("enclosures") or []
        if not image_url and enclosures:
            image_url = enclosures[0].get("href")
        results.append(
            {
                "id": _hash_id("rss", link),
                "title": title.strip()[:512],
                "url": link,
                "source": source_name,
                "description": description,
                "image_url": image_url,
                "published_at": published,
                "category": categorize(title, description),
            }
        )
    return results


async def _fetch_rss_feeds() -> list[dict[str, Any]]:
    if not settings.news_rss_feeds:
        return []
    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, _parse_feed_sync, url) for url in settings.news_rss_feeds]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    flat: list[dict[str, Any]] = []
    for r in results:
        if isinstance(r, list):
            flat.extend(r)
        elif isinstance(r, Exception):
            logger.warning("RSS feed failed: %s", r)
    return flat


async def _purge_stale(db: AsyncSession) -> None:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=settings.news_retention_hours)
    await db.execute(delete(NewsArticle).where(NewsArticle.published_at < cutoff))


async def ingest_news(db: AsyncSession) -> tuple[int, int]:
    """Fetch news from all sources, dedupe, upsert. Returns (inserted, total_fetched)."""
    from app.models.ingestion_log import IngestionLog

    log = IngestionLog(
        source="news",
        status="running",
        started_at=datetime.now(tz=timezone.utc),
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)

    t0 = datetime.now(tz=timezone.utc)
    try:
        timeout = httpx.Timeout(30.0, connect=10.0)
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "SentinelX/1.0"},
        ) as client:
            api_articles = await _fetch_newsapi(client)
            rss_articles = await _fetch_rss_feeds()

        combined: dict[str, dict[str, Any]] = {}
        seen_titles: set[str] = set()
        now = datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(hours=settings.news_retention_hours)

        for item in [*api_articles, *rss_articles]:
            if item["published_at"] < cutoff:
                continue
            title_key = item["title"].lower().strip()
            if title_key in seen_titles:
                continue
            if item["url"] in combined:
                continue
            combined[item["url"]] = item
            seen_titles.add(title_key)

        await _purge_stale(db)

        inserted = updated = 0
        for payload in combined.values():
            existing = await db.execute(
                select(NewsArticle).where(NewsArticle.url == payload["url"])
            )
            obj = existing.scalar_one_or_none()
            if obj is None:
                obj = NewsArticle(**payload, fetched_at=now)
                db.add(obj)
                inserted += 1
            else:
                obj.title = payload["title"]
                obj.source = payload["source"]
                obj.category = payload["category"]
                obj.description = payload["description"]
                obj.image_url = payload["image_url"]
                updated += 1

        await db.commit()

        log.total_fetched = len(api_articles) + len(rss_articles)
        log.inserted = inserted
        log.updated = updated
        log.status = "success"

        logger.info(
            "News ingest: %s new, %s total fetched, %s retained",
            inserted,
            log.total_fetched,
            len(combined),
        )
        return inserted, len(combined)
    except Exception as exc:  # noqa: BLE001
        log.status = "failed"
        log.error_message = str(exc)[:1000]
        logger.exception("news ingest failed")
        raise
    finally:
        log.finished_at = datetime.now(tz=timezone.utc)
        log.duration_seconds = (log.finished_at - t0).total_seconds()
        await db.commit()


async def run_scheduled_news_ingest() -> None:
    async with SessionLocal() as session:
        try:
            await ingest_news(session)
        except Exception:  # noqa: BLE001
            logger.exception("Scheduled news ingest failed")


async def list_news(
    db: AsyncSession,
    category: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> Iterable[NewsArticle]:
    from sqlalchemy import and_, or_

    stmt = select(NewsArticle)
    filters = []
    if category:
        filters.append(NewsArticle.category == category)
    if search:
        like = f"%{search.strip()}%"
        filters.append(or_(NewsArticle.title.ilike(like), NewsArticle.description.ilike(like)))
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(NewsArticle.published_at.desc()).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())
