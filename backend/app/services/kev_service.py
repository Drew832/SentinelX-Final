"""CISA Known Exploited Vulnerabilities (KEV) ingestion.

Stores every KEV row in the dedicated `kev_entries` table (authoritative) and
mirrors the flag / metadata onto matching `cves` rows for filtering. Wraps the
entire sync in try/except so a CISA outage logs a warning but never crashes
the app.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import SessionLocal
from app.models.cve import CVE
from app.models.ingestion_log import IngestionLog
from app.models.kev_entry import KevEntry

logger = logging.getLogger(__name__)


KEV_URLS: Tuple[str, ...] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog.json",
    "https://raw.githubusercontent.com/cisagov/known_exploited_vulnerabilities/main/known_exploited_vulnerabilities.json",
)

BATCH_SIZE = 500


# ---------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def fetch_kev_catalog() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Try each fallback URL in order. Returns ([], None) if all fail."""
    timeout = httpx.Timeout(60.0, connect=10.0)
    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": "SentinelX/1.0"}
    ) as client:
        for url in KEV_URLS:
            try:
                resp = await client.get(url)
                if resp.status_code >= 400:
                    logger.warning(
                        "KEV sync: tried URL %s, got status %s", url, resp.status_code
                    )
                    continue
                data = resp.json()
                vulns = data.get("vulnerabilities") or []
                logger.info("KEV sync: tried URL %s, got %s entries", url, len(vulns))
                if vulns:
                    return vulns, url
            except Exception as exc:  # noqa: BLE001
                logger.warning("KEV sync: tried URL %s, failed: %s", url, exc)
    return [], None


# ---------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------


async def _chunks(seq: Sequence[Any], size: int = BATCH_SIZE):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


async def _upsert_kev_entries(
    db: AsyncSession, entries: List[Dict[str, Any]], source_url: Optional[str]
) -> Tuple[int, int]:
    """Upsert into `kev_entries`, deduped on cve_id. Returns (inserted, updated)."""
    inserted = updated = 0
    now = datetime.now(tz=timezone.utc)
    existing_ids: set = set()

    # Chunked existence check.
    ids = [str(e.get("cveID") or "").upper() for e in entries if e.get("cveID")]
    async for chunk in _chunks(ids, BATCH_SIZE):
        rows = (
            await db.execute(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(chunk)))
        ).scalars().all()
        existing_ids.update(rows)

    for raw in entries:
        cve_id = (raw.get("cveID") or "").upper()
        if not cve_id:
            continue
        payload = {
            "cve_id": cve_id,
            "vendor_project": raw.get("vendorProject"),
            "product": raw.get("product"),
            "vulnerability_name": raw.get("vulnerabilityName"),
            "short_description": raw.get("shortDescription"),
            "required_action": raw.get("requiredAction"),
            "known_ransomware": raw.get("knownRansomwareCampaignUse"),
            "notes": raw.get("notes"),
            "date_added": _parse_date(raw.get("dateAdded")),
            "due_date": _parse_date(raw.get("dueDate")),
            "source_url": source_url,
            "is_active": True,
            "last_synced_at": now,
        }
        if cve_id in existing_ids:
            existing = (
                await db.execute(select(KevEntry).where(KevEntry.cve_id == cve_id))
            ).scalar_one()
            for k, v in payload.items():
                setattr(existing, k, v)
            updated += 1
        else:
            payload["first_seen_at"] = now
            db.add(KevEntry(**payload))
            inserted += 1

    await db.commit()
    return inserted, updated


async def _flag_matching_cves(db: AsyncSession, entries: List[Dict[str, Any]]) -> int:
    """Set `is_kev=True` plus KEV metadata on every matching CVE row (batched)."""
    # Reset stale flags first so removed entries are demoted.
    await db.execute(update(CVE).where(CVE.is_kev.is_(True)).values(is_kev=False))
    await db.commit()

    flagged = 0
    cve_id_index = {
        (e.get("cveID") or "").upper(): e for e in entries if e.get("cveID")
    }
    ids = list(cve_id_index.keys())

    async for batch in _chunks(ids, BATCH_SIZE):
        rows = (
            await db.execute(select(CVE).where(CVE.cve_id.in_(batch)))
        ).scalars().all()
        for cve in rows:
            raw = cve_id_index.get(cve.cve_id)
            if not raw:
                continue
            cve.is_kev = True
            cve.kev_date_added = _parse_date(raw.get("dateAdded"))
            cve.kev_due_date = _parse_date(raw.get("dueDate"))
            cve.kev_vendor_project = raw.get("vendorProject")
            cve.kev_product = raw.get("product")
            cve.kev_vulnerability_name = raw.get("vulnerabilityName")
            cve.kev_required_action = raw.get("requiredAction")
            cve.kev_ransomware_use = raw.get("knownRansomwareCampaignUse")
            flagged += 1
        await db.commit()

    return flagged


# ---------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------


async def sync_kev(db: Optional[AsyncSession] = None) -> Dict[str, int]:
    """Full KEV sync. Always returns counters; never raises to the caller."""
    owns_session = db is None
    session: AsyncSession = db if db is not None else SessionLocal()

    log_row = IngestionLog(
        source="kev",
        status="running",
        started_at=datetime.now(tz=timezone.utc),
    )
    session.add(log_row)
    await session.commit()
    await session.refresh(log_row)
    t0 = datetime.now(tz=timezone.utc)

    counters = {"new": 0, "updated": 0, "flagged": 0, "total": 0}

    try:
        entries, source_url = await fetch_kev_catalog()
        counters["total"] = len(entries)
        if not entries:
            logger.warning("KEV sync: all fallback URLs failed, skipping")
            log_row.status = "failed"
            log_row.error_message = "All KEV URLs unavailable"
            return counters

        inserted, updated = await _upsert_kev_entries(session, entries, source_url)
        counters["new"] = inserted
        counters["updated"] = updated

        flagged = await _flag_matching_cves(session, entries)
        counters["flagged"] = flagged

        log_row.total_fetched = counters["total"]
        log_row.inserted = counters["new"]
        log_row.updated = counters["updated"]
        log_row.status = "success"

        logger.info(
            "KEV sync done: %s new, %s updated, %s CVEs flagged",
            counters["new"],
            counters["updated"],
            counters["flagged"],
        )
    except Exception as exc:  # noqa: BLE001
        log_row.status = "failed"
        log_row.error_message = str(exc)[:1000]
        logger.warning("KEV sync failed, continuing without update: %s", exc)
    finally:
        log_row.finished_at = datetime.now(tz=timezone.utc)
        log_row.duration_seconds = (log_row.finished_at - t0).total_seconds()
        try:
            await session.commit()
        except Exception:  # noqa: BLE001
            pass
        if owns_session:
            await session.close()

    return counters


async def run_scheduled_kev_ingest() -> None:
    """APScheduler entry — runs every 6 hours."""
    try:
        await sync_kev()
    except Exception:  # noqa: BLE001
        logger.warning("Scheduled KEV sync failed (non-fatal)")


# ---------------------------------------------------------------
# Back-compat with existing admin endpoint
# ---------------------------------------------------------------


async def ingest_kev(db: AsyncSession) -> Tuple[int, int]:
    """Legacy wrapper used by `/admin/ingest/kev`. Returns (matched, total)."""
    result = await sync_kev(db)
    return result.get("flagged", 0), result.get("total", 0)
