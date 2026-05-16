"""CISA KEV dashboard API."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.cve import CVE

router = APIRouter(prefix="/kev", tags=["kev"])


@router.get("")
async def list_kev(
    db: AsyncSession = Depends(get_db),
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    ransomware_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> dict:
    filters = [CVE.is_kev.is_(True)]
    if vendor:
        filters.append(func.lower(CVE.kev_vendor_project).ilike(f"%{vendor.lower()}%"))
    if product:
        filters.append(func.lower(CVE.kev_product).ilike(f"%{product.lower()}%"))
    if search:
        like = f"%{search.strip()}%"
        filters.append(
            or_(
                CVE.cve_id.ilike(like),
                CVE.description.ilike(like),
                CVE.kev_vulnerability_name.ilike(like),
            )
        )
    if ransomware_only:
        filters.append(func.lower(CVE.kev_ransomware_use).in_(["known", "yes", "true"]))

    stmt = select(CVE).where(and_(*filters)).order_by(
        CVE.kev_date_added.desc().nullslast(),
        CVE.cvss_v3_score.desc().nullslast(),
    )

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).scalars().all()

    # Vendor aggregation for the dashboard filters
    vendor_rows = await db.execute(
        select(CVE.kev_vendor_project, func.count(CVE.cve_id))
        .where(CVE.is_kev.is_(True))
        .group_by(CVE.kev_vendor_project)
    )
    vendors = [
        {"vendor": v or "Unknown", "count": c}
        for v, c in vendor_rows.all()
        if v
    ]
    vendors.sort(key=lambda x: -x["count"])

    # Simple statistics banner
    totals = await db.execute(
        select(
            func.count(CVE.cve_id).filter(CVE.is_kev.is_(True)),
            func.count(CVE.cve_id).filter(
                and_(CVE.is_kev.is_(True), func.lower(CVE.kev_ransomware_use) == "known")
            ),
        )
    )
    total_kev, ransomware_count = totals.one()

    items = []
    for c in rows:
        items.append(
            {
                "cve_id": c.cve_id,
                "vendor": c.kev_vendor_project,
                "product": c.kev_product,
                "vulnerability_name": c.kev_vulnerability_name,
                "description": c.description,
                "date_added": c.kev_date_added.isoformat() if c.kev_date_added else None,
                "due_date": c.kev_due_date.isoformat() if c.kev_due_date else None,
                "required_action": c.kev_required_action,
                "ransomware_use": c.kev_ransomware_use,
                "cvss_v3_score": c.cvss_v3_score,
                "cvss_v3_severity": c.cvss_v3_severity,
            }
        )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
        "vendors": vendors[:20],
        "banner": {
            "total_kev": total_kev,
            "ransomware_linked": ransomware_count,
        },
    }


@router.get("/stats")
async def kev_stats(db: AsyncSession = Depends(get_db)) -> dict:
    total = (
        await db.execute(select(func.count(CVE.cve_id)).where(CVE.is_kev.is_(True)))
    ).scalar_one()
    ransomware = (
        await db.execute(
            select(func.count(CVE.cve_id)).where(
                and_(
                    CVE.is_kev.is_(True),
                    func.lower(CVE.kev_ransomware_use) == "known",
                )
            )
        )
    ).scalar_one()
    return {"total_kev": total, "ransomware_linked": ransomware}
