"""NIST NVD API v2 ingestion service.

Supports two filter modes:

* **pubStartDate / pubEndDate** (use_last_modified=False) — filters by CVE
  publication date. Used once on startup to seed an empty database with the
  last N days of CVEs.
* **lastModStartDate / lastModEndDate** (use_last_modified=True) — filters by
  the last time NVD modified a CVE (CVSS score attached, status change,
  description edit). Used every 10 minutes so updates to old CVEs are captured.

The module also exposes `fetch_cves` for tests and a boolean `_ingestion_running`
lock consumed by the scheduler to prevent overlapping runs.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.cve import CVE
from app.models.ingestion_log import IngestionLog

logger = logging.getLogger(__name__)


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DATE_FMT = "%Y-%m-%dT%H:%M:%S.000"
PAGE_SIZE = 2000
MAX_WINDOW_DAYS = 120

# Process-wide lock preventing the APScheduler interval job from stacking.
_ingestion_running: bool = False


# ---------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------


def format_nvd_timestamp(dt: datetime) -> str:
    """Return an NVD-compatible timestamp string (millisecond precision, no offset)."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime(NVD_DATE_FMT)


def _headers() -> Dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "SentinelX/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    return headers


def _request_delay() -> float:
    """Polite per-page delay (0.7s with key, 6s without) — respects 50 reqs / 30s."""
    return 0.7 if settings.nvd_api_key else 6.0


# ---------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------


def _pick_primary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Prefer the metric entry with type=="Primary" over "Secondary"."""
    for it in items:
        if (it.get("type") or "").lower() == "primary":
            return it
    return items[0]


def _parse_metric(metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not metrics:
        return out

    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if items:
            entry = _pick_primary(items)
            data = entry.get("cvssData") or {}
            out["cvss_v3_score"] = data.get("baseScore")
            sev = data.get("baseSeverity")
            out["cvss_v3_severity"] = (sev or "").upper() or None
            out["cvss_v3_vector"] = data.get("vectorString")
            break

    items_v2 = metrics.get("cvssMetricV2") or []
    if items_v2:
        entry = _pick_primary(items_v2)
        data = entry.get("cvssData") or {}
        out["cvss_v2_score"] = data.get("baseScore")
        # For v2, baseSeverity lives on the metric entry itself — NOT in cvssData.
        out["cvss_v2_severity"] = (entry.get("baseSeverity") or "").upper() or None
        out["cvss_v2_vector"] = data.get("vectorString")

    # If v3 severity is missing but v2 has one, fall back.
    if not out.get("cvss_v3_severity") and out.get("cvss_v2_severity"):
        out["cvss_v3_severity"] = out["cvss_v2_severity"]

    return out


def _parse_description(descriptions: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    if not descriptions:
        return None
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return descriptions[0].get("value")


def _is_reserved_or_rejected(description: Optional[str]) -> bool:
    if not description:
        return False
    return "** RESERVED **" in description or "** REJECT **" in description


def _parse_cwes(weaknesses: Optional[List[Dict[str, Any]]]) -> List[str]:
    cwes: List[str] = []
    if not weaknesses:
        return cwes
    for w in weaknesses:
        for d in w.get("description", []) or []:
            value = d.get("value")
            if value and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _walk_cpe_nodes(
    nodes: Optional[List[Dict[str, Any]]],
    out_cpes: List[Dict[str, Any]],
    vendors_seen: set,
) -> None:
    """Recursively collect `cpeMatch` entries from `nodes` and `nodes.children`."""
    if not nodes:
        return
    for node in nodes:
        for match in node.get("cpeMatch", []) or []:
            # Only keep entries where vulnerable == True.
            if not match.get("vulnerable"):
                continue
            criteria = match.get("criteria") or ""
            parts = criteria.split(":")
            vendor = parts[3] if len(parts) > 4 else None
            product = parts[4] if len(parts) > 5 else None
            version = parts[5] if len(parts) > 6 else None
            out_cpes.append(
                {
                    "criteria": criteria,
                    "vulnerable": True,
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                }
            )
            if vendor:
                vendors_seen.add(vendor)
        _walk_cpe_nodes(node.get("children") or [], out_cpes, vendors_seen)


def _parse_cpes_and_vendors(
    configurations: Optional[List[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    cpes: List[Dict[str, Any]] = []
    vendors_seen: set = set()
    for config in configurations or []:
        _walk_cpe_nodes(config.get("nodes") or [], cpes, vendors_seen)
    return cpes, sorted(vendors_seen)


def _parse_references(refs: Optional[List[Dict[str, Any]]]) -> List[str]:
    if not refs:
        return []
    return [r.get("url") for r in refs if r.get("url")]


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def normalize_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise one NVD `vulnerabilities[*]` entry.

    Returns None for entries that should be skipped (RESERVED/REJECT or no
    published date).
    """
    # Always access via v["cve"].
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = _parse_description(cve.get("descriptions"))
    if _is_reserved_or_rejected(description):
        return None

    published = _parse_dt(cve.get("published"))
    if not published:
        return None

    metrics = _parse_metric(cve.get("metrics"))
    cpes, vendors = _parse_cpes_and_vendors(cve.get("configurations"))

    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": published,
        "last_modified_date": _parse_dt(cve.get("lastModified")),
        "cvss_v3_score": metrics.get("cvss_v3_score"),
        "cvss_v3_severity": metrics.get("cvss_v3_severity"),
        "cvss_v3_vector": metrics.get("cvss_v3_vector"),
        "cvss_v2_score": metrics.get("cvss_v2_score"),
        "cvss_v2_severity": metrics.get("cvss_v2_severity"),
        "cvss_v2_vector": metrics.get("cvss_v2_vector"),
        "cwe_ids": _parse_cwes(cve.get("weaknesses")),
        "cpe_products": cpes,
        "vendors": vendors,
        "references": _parse_references(cve.get("references")),
        "source_identifier": cve.get("sourceIdentifier"),
        "vuln_status": cve.get("vulnStatus"),
        "raw": cve,
    }


# ---------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------


async def _fetch_page(
    client: httpx.AsyncClient,
    params: Dict[str, Any],
    attempt: int = 0,
) -> Optional[Dict[str, Any]]:
    """Fetch one page with the required NVD retry etiquette."""
    try:
        resp = await client.get(
            NVD_ENDPOINT,
            params=params,
            headers=_headers(),
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
    except httpx.HTTPError as exc:
        if attempt >= 4:
            logger.error("NVD network error (giving up): %s", exc)
            return None
        backoff = 6 * (2 ** attempt)
        logger.warning(
            "NVD network error attempt=%s sleeping=%ss err=%s", attempt, backoff, exc
        )
        await asyncio.sleep(backoff)
        return await _fetch_page(client, params, attempt + 1)

    # 403 → rate-limited at the gateway; doc says wait 30s then retry.
    if resp.status_code == 403:
        if attempt >= 5:
            logger.error("NVD 403 after retries; giving up on this page")
            return None
        logger.warning("NVD 403 — sleeping 30s then retrying")
        await asyncio.sleep(30)
        return await _fetch_page(client, params, attempt + 1)

    # 429 / 503 → exponential backoff starting at 6s.
    if resp.status_code in (429, 503):
        if attempt >= 5:
            logger.error("NVD %s after retries; giving up on this page", resp.status_code)
            return None
        backoff = 6 * (2 ** attempt)
        logger.warning(
            "NVD %s — sleeping %ss (attempt %s)", resp.status_code, backoff, attempt
        )
        await asyncio.sleep(backoff)
        return await _fetch_page(client, params, attempt + 1)

    if resp.status_code >= 400:
        logger.error("NVD %s unrecoverable: %s", resp.status_code, resp.text[:250])
        return None

    try:
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.error("NVD non-JSON payload: %s", exc)
        return None


async def fetch_cves(
    start: datetime,
    end: datetime,
    use_last_modified: bool = False,
) -> List[Dict[str, Any]]:
    """Return all CVE envelopes in the window. Handles pagination for the caller.

    When use_last_modified=False → pubStartDate / pubEndDate (seeding).
    When use_last_modified=True  → lastModStartDate / lastModEndDate (polling).
    """
    if start.tzinfo is not None:
        start = start.astimezone(timezone.utc).replace(tzinfo=None)
    if end.tzinfo is not None:
        end = end.astimezone(timezone.utc).replace(tzinfo=None)

    start_key = "lastModStartDate" if use_last_modified else "pubStartDate"
    end_key = "lastModEndDate" if use_last_modified else "pubEndDate"

    results: List[Dict[str, Any]] = []
    start_index = 0
    delay = _request_delay()

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
        while True:
            params = {
                start_key: format_nvd_timestamp(start),
                end_key: format_nvd_timestamp(end),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            data = await _fetch_page(client, params)
            if not data:
                break

            vulns = data.get("vulnerabilities") or []
            total = int(data.get("totalResults") or 0)
            logger.info(
                "NVD: fetched %s/%s from page starting at index %s",
                len(vulns),
                total,
                start_index,
            )

            if not vulns:
                break
            results.extend(vulns)

            start_index += PAGE_SIZE
            if start_index >= total:
                break
            await asyncio.sleep(delay)

    return results


# ---------------------------------------------------------------
# Upsert + top-level ingest
# ---------------------------------------------------------------


async def _upsert(db: AsyncSession, payload: Dict[str, Any]) -> Optional[bool]:
    """Insert if new, update only when last_modified actually changed.

    Returns True on insert, False on update, None on no-op / skip.
    """
    if not payload.get("cve_id"):
        return None

    stmt = select(CVE).where(CVE.cve_id == payload["cve_id"])
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing is None:
        db.add(CVE(**payload))
        return True

    incoming = payload.get("last_modified_date")
    current = existing.last_modified_date
    if incoming and current:
        if incoming.tzinfo is None:
            incoming = incoming.replace(tzinfo=timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if incoming <= current:
            return None

    for k, v in payload.items():
        setattr(existing, k, v)
    return False


def _split_windows(
    start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS
) -> List[Tuple[datetime, datetime]]:
    out: List[Tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=max_days), end)
        out.append((cursor, window_end))
        cursor = window_end
    return out


async def run_ingestion(
    days_back: int = 1,
    use_last_modified: bool = True,
    db: Optional[AsyncSession] = None,
) -> Dict[str, int]:
    """Ingest CVEs for the last `days_back` days.

    When `use_last_modified` is False we fetch using `pubStartDate` /
    `pubEndDate` (seed mode). When True we fetch using `lastModStartDate` /
    `lastModEndDate` (polling mode).

    Returns a dict with `new`, `updated`, `skipped`, `failed`, `total_fetched`.
    """
    global _ingestion_running
    if _ingestion_running:
        logger.info("CVE ingestion skipped — previous run still in progress")
        return {"new": 0, "updated": 0, "skipped": 0, "failed": 0, "total_fetched": 0}

    _ingestion_running = True
    owns_session = db is None
    session: AsyncSession = db if db is not None else SessionLocal()

    end = datetime.now(tz=timezone.utc)
    start = end - timedelta(days=days_back)
    mode = "last_modified" if use_last_modified else "published"
    source = "nvd.polling" if use_last_modified else "nvd.seed"

    logger.info(
        "CVE ingestion started | mode=%s | range=%s → %s",
        mode,
        start.isoformat(),
        end.isoformat(),
    )

    log_row = IngestionLog(
        source=source,
        status="running",
        window_start=start,
        window_end=end,
        started_at=datetime.now(tz=timezone.utc),
    )
    session.add(log_row)
    await session.commit()
    await session.refresh(log_row)
    t0 = datetime.now(tz=timezone.utc)

    counters = {"new": 0, "updated": 0, "skipped": 0, "failed": 0, "total_fetched": 0}

    try:
        for w_start, w_end in _split_windows(start, end):
            envelopes = await fetch_cves(w_start, w_end, use_last_modified=use_last_modified)
            counters["total_fetched"] += len(envelopes)
            for env in envelopes:
                try:
                    payload = normalize_cve(env)
                    if payload is None:
                        counters["skipped"] += 1
                        continue
                    result = await _upsert(session, payload)
                    if result is True:
                        counters["new"] += 1
                    elif result is False:
                        counters["updated"] += 1
                    else:
                        counters["skipped"] += 1
                except Exception as exc:  # noqa: BLE001
                    counters["failed"] += 1
                    logger.warning("Failed to process NVD item: %s", exc)
            await session.commit()

        log_row.total_fetched = counters["total_fetched"]
        log_row.inserted = counters["new"]
        log_row.updated = counters["updated"]
        log_row.failed = counters["failed"]
        log_row.status = "success"

        logger.info(
            "Ingestion done: %s new, %s updated (skipped=%s, failed=%s, fetched=%s)",
            counters["new"],
            counters["updated"],
            counters["skipped"],
            counters["failed"],
            counters["total_fetched"],
        )
        return counters
    except Exception as exc:  # noqa: BLE001
        log_row.status = "failed"
        log_row.error_message = str(exc)[:1000]
        logger.exception("CVE ingestion failed")
        return counters
    finally:
        log_row.finished_at = datetime.now(tz=timezone.utc)
        log_row.duration_seconds = (log_row.finished_at - t0).total_seconds()
        try:
            await session.commit()
        except Exception:  # noqa: BLE001
            pass
        if owns_session:
            await session.close()
        _ingestion_running = False


# ---------------------------------------------------------------
# Scheduler / startup entry points
# ---------------------------------------------------------------


async def run_scheduled_nvd_ingest() -> None:
    """Every-10-minute APScheduler job — polling mode."""
    try:
        result = await run_ingestion(days_back=1, use_last_modified=True)
        if (result.get("new") or 0) + (result.get("updated") or 0) > 0:
            try:
                async with SessionLocal() as s:
                    from app.services.risk_scoring import rescore_all_profiles

                    await rescore_all_profiles(s)
            except Exception:  # noqa: BLE001
                logger.exception("Profile rescore after polling ingest failed")
    except Exception:  # noqa: BLE001
        logger.exception("Scheduled CVE polling failed")


async def run_initial_nvd_ingest() -> bool:
    """Called from the lifespan on startup.

    Seeds the last 30 days of published CVEs on an empty database. If the DB
    already has CVEs, logs and returns False without fetching.

    Returns True when a seed actually happened.
    """
    if not settings.nvd_run_initial_ingest:
        logger.info("Initial NVD ingest disabled via config")
        return False
    try:
        async with SessionLocal() as session:
            count = (await session.execute(select(func.count(CVE.cve_id)))).scalar_one()
            if count > 0:
                logger.info(
                    "DB has %s CVEs, skipping initial fetch (use_last_modified=False)",
                    count,
                )
                return False
            logger.info(
                "Starting initial CVE seed for last %s days", settings.nvd_initial_fetch_days
            )
            await run_ingestion(
                days_back=settings.nvd_initial_fetch_days,
                use_last_modified=False,
                db=session,
            )
            return True
    except Exception:  # noqa: BLE001
        logger.exception("Initial CVE ingestion failed")
        return False


# ---------------------------------------------------------------
# Back-compat shims for older callers
# ---------------------------------------------------------------


async def ingest_recent_nvd(
    db: AsyncSession,
    minutes: Optional[int] = None,
    end: Optional[datetime] = None,
) -> Tuple[int, int]:
    """Legacy wrapper — kept so `/admin/ingest/nvd?minutes=` keeps working."""
    minutes = minutes or 10
    # Run in polling mode on an explicit short window using the shared pipeline.
    result = await run_ingestion(
        days_back=max(1, (minutes + 1440 - 1) // 1440),
        use_last_modified=True,
        db=db,
    )
    return result["new"], result["updated"]


async def ingest_nvd_window(
    db: AsyncSession,
    start: datetime,
    end: datetime,
    source: str = "nvd",
) -> IngestionLog:
    """Legacy wrapper for the admin backfill endpoint.

    Decides mode based on window length — short windows (<= 2 days) use polling
    mode; longer ones use pubStartDate because NVD's lastMod window only
    captures records that changed in that span.
    """
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    span_days = max(1, (end - start).days)
    use_last_modified = span_days <= 2
    result = await run_ingestion(
        days_back=span_days,
        use_last_modified=use_last_modified,
        db=db,
    )
    # Return the most recent ingestion log row for compat with the admin route.
    row = (
        await db.execute(
            select(IngestionLog).order_by(IngestionLog.started_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    # Fallback stub if no row is found (should not happen in practice).
    if row is None:
        row = IngestionLog(
            source=source,
            status="success",
            window_start=start,
            window_end=end,
            total_fetched=result.get("total_fetched", 0),
            inserted=result.get("new", 0),
            updated=result.get("updated", 0),
            failed=result.get("failed", 0),
        )
    return row
