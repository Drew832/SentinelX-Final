"""CVE Explorer API endpoints."""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import String, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.models.cve import CVE
from app.models.user import User
from app.schemas.cve import (
    CVEListResponse,
    CVEOut,
    SeverityBucket,
    StatsResponse,
    TrendPoint,
    VendorBucket,
)
from app.services.export_service import cves_to_csv, cves_to_xlsx

router = APIRouter(prefix="/cves", tags=["cves"])


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _is_guest(user: Optional[User]) -> bool:
    return user is None


@router.get("", response_model=CVEListResponse)
async def list_cves(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_current_user_optional),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = Query(None, description="Free text search on CVE ID/description"),
    severity: Optional[str] = Query(None, description="CRITICAL/HIGH/MEDIUM/LOW"),
    only_kev: bool = Query(False, description="Filter to CISA KEV vulnerabilities only"),
    min_score: Optional[float] = Query(None, ge=0, le=10),
    max_score: Optional[float] = Query(None, ge=0, le=10),
    sort: str = Query("modified_desc"),
    published_after: Optional[date] = Query(
        None, description="Include CVEs published on or after this date (UTC date)"
    ),
    published_before: Optional[date] = Query(
        None, description="Include CVEs published on or before this date (UTC date)"
    ),
) -> CVEListResponse:
    if _is_guest(user):
        page_size = min(page_size, 25)

    stmt = select(CVE)
    filters = []

    if search:
        like = f"%{search.strip()}%"
        filters.append(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
    if severity:
        filters.append(CVE.cvss_v3_severity == severity.upper())
    if only_kev:
        filters.append(CVE.is_kev.is_(True))
    if min_score is not None:
        filters.append(CVE.cvss_v3_score >= min_score)
    if max_score is not None:
        filters.append(CVE.cvss_v3_score <= max_score)
    if published_after is not None:
        start_dt = datetime.combine(published_after, time.min, tzinfo=timezone.utc)
        filters.append(CVE.published_date >= start_dt)
    if published_before is not None:
        end_exclusive = datetime.combine(
            published_before + timedelta(days=1), time.min, tzinfo=timezone.utc
        )
        filters.append(CVE.published_date < end_exclusive)

    if filters:
        stmt = stmt.where(and_(*filters))

    if sort == "score_desc":
        stmt = stmt.order_by(CVE.cvss_v3_score.desc().nullslast())
    elif sort == "published_desc":
        stmt = stmt.order_by(CVE.published_date.desc().nullslast())
    else:
        stmt = stmt.order_by(CVE.last_modified_date.desc().nullslast())

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return CVEListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[CVEOut.model_validate(r) for r in rows],
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(db: AsyncSession = Depends(get_db)) -> StatsResponse:
    total = (await db.execute(select(func.count(CVE.cve_id)))).scalar_one()
    kev_count = (
        await db.execute(select(func.count(CVE.cve_id)).where(CVE.is_kev.is_(True)))
    ).scalar_one()

    severity_buckets: list[SeverityBucket] = []
    severity_counts: dict[str, int] = {sev: 0 for sev in SEVERITIES}
    unscored = 0
    rows = await db.execute(
        select(CVE.cvss_v3_severity, func.count(CVE.cve_id)).group_by(CVE.cvss_v3_severity)
    )
    for sev, cnt in rows.all():
        if not sev:
            unscored += cnt
            continue
        key = sev.upper()
        if key in severity_counts:
            severity_counts[key] = severity_counts.get(key, 0) + cnt
        else:
            # Anything NVD has tagged as e.g. NONE / UNKNOWN bucketed as unscored.
            unscored += cnt
    for sev in SEVERITIES:
        severity_buckets.append(SeverityBucket(severity=sev, count=severity_counts.get(sev, 0)))
    severity_buckets.append(SeverityBucket(severity="UNSCORED", count=unscored))

    vendor_counter: Counter[str] = Counter()
    vendor_rows = await db.execute(
        select(CVE.vendors).where(CVE.vendors.isnot(None)).order_by(
            CVE.last_modified_date.desc().nullslast()
        ).limit(5000)
    )
    for (vendors,) in vendor_rows.all():
        if not vendors:
            continue
        for v in vendors:
            if v:
                vendor_counter[v] += 1
    top_vendors = [VendorBucket(vendor=v, count=c) for v, c in vendor_counter.most_common(10)]

    today = datetime.now(tz=timezone.utc).date()
    trend: list[TrendPoint] = []
    start = today - timedelta(days=13)
    trend_rows = await db.execute(
        select(CVE.published_date).where(CVE.published_date >= datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc))
    )
    bucket: dict[str, int] = {(start + timedelta(days=i)).isoformat(): 0 for i in range(14)}
    for (pub,) in trend_rows.all():
        if not pub:
            continue
        d = pub.date().isoformat()
        if d in bucket:
            bucket[d] += 1
    for d, c in bucket.items():
        trend.append(TrendPoint(date=d, count=c))

    last_ingest_row = await db.execute(
        select(func.max(CVE.updated_at))
    )
    last_ingest = last_ingest_row.scalar_one_or_none()

    categorized = sum(severity_counts.get(s, 0) for s in SEVERITIES)
    return StatsResponse(
        total_cves=total,
        kev_count=kev_count,
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
        unscored_count=unscored,
        categorized_total=categorized,
        severity_distribution=severity_buckets,
        top_vendors=top_vendors,
        trend_14d=trend,
        trend_window_days=14,
        last_ingest=last_ingest,
    )


@router.get("/top-priority", response_model=list[dict])
async def top_priority(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(5, ge=1, le=25),
    criticality: int = Query(5, ge=1, le=5),
) -> list[dict]:
    """Globally top-N CVEs by priority_score using the supplied criticality.

    Intended for the Action Center panel on the dashboard where no specific
    profile is selected yet.
    """
    from app.services.risk_scoring import compute_priority_score

    stmt = (
        select(CVE)
        .where(or_(CVE.is_kev.is_(True), CVE.cvss_v3_score >= 7.0))
        .order_by(CVE.cvss_v3_score.desc().nullslast())
        .limit(200)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    prioritized = []
    for c in rows:
        score, weight = compute_priority_score(c, criticality)
        prioritized.append(
            {
                "cve_id": c.cve_id,
                "cvss_v3_score": c.cvss_v3_score,
                "cvss_v3_severity": c.cvss_v3_severity,
                "is_kev": c.is_kev,
                "is_exploited": c.is_kev,
                "priority_score": score,
                "exploit_weight": weight,
                "description": (c.description or "")[:240],
                "vendors": c.vendors or [],
                "published_date": c.published_date.isoformat() if c.published_date else None,
            }
        )
    prioritized.sort(key=lambda p: p["priority_score"], reverse=True)
    return prioritized[:limit]


@router.get("/critical", response_model=list[CVEOut])
async def list_critical(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[CVEOut]:
    stmt = (
        select(CVE)
        .where(or_(CVE.cvss_v3_severity == "CRITICAL", CVE.cvss_v3_score >= 9.0))
        .order_by(CVE.published_date.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return [CVEOut.model_validate(c) for c in result.scalars().all()]


@router.get("/export")
async def export_cves(
    db: AsyncSession = Depends(get_db),
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    only_kev: bool = Query(False),
    severity: str | None = Query(None),
    search: str | None = Query(None),
    vendor: str | None = Query(None),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    min_score: float | None = Query(None, ge=0, le=10),
    max_score: float | None = Query(None, ge=0, le=10),
    limit: int = Query(5000, ge=1, le=20000),
):
    filters = []
    if only_kev:
        filters.append(CVE.is_kev.is_(True))
    if severity:
        filters.append(CVE.cvss_v3_severity == severity.upper())
    if search:
        like = f"%{search.strip()}%"
        filters.append(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
    if vendor:
        vendor_like = f"%{vendor.strip().lower()}%"
        # vendors is a JSON list; substring match on its serialised form is a
        # pragmatic approximation that works on both SQLite and Postgres.
        filters.append(func.lower(func.cast(CVE.vendors, String)).like(vendor_like))
    if start_date:
        filters.append(CVE.published_date >= start_date)
    if end_date:
        filters.append(CVE.published_date <= end_date)
    if min_score is not None:
        filters.append(CVE.cvss_v3_score >= min_score)
    if max_score is not None:
        filters.append(CVE.cvss_v3_score <= max_score)

    stmt = select(CVE)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(CVE.last_modified_date.desc().nullslast()).limit(limit)

    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    if format == "xlsx":
        payload = cves_to_xlsx(rows)
        media_type = (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        filename = f"sentinelx-cves-{len(rows)}.xlsx"
    else:
        payload = cves_to_csv(rows)
        media_type = "text/csv"
        filename = f"sentinelx-cves-{len(rows)}.csv"

    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{cve_id}", response_model=CVEOut)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)) -> CVEOut:
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return CVEOut.model_validate(cve)
