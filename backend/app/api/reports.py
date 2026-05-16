"""Executive and technical report API with PDF, Excel, and CSV export."""
from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.profile import OrgProfile
from app.models.user import User
from app.services.reporting import (
    export_report_bytes,
    generate_executive_report,
    generate_technical_report,
    strip_internal,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


async def _get_profile(db: AsyncSession, profile_id: int) -> OrgProfile:
    result = await db.execute(select(OrgProfile).where(OrgProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


def _resolve_window(start: date | None, end: date | None) -> tuple[date, date]:
    today = date.today()
    resolved_end = end or today
    resolved_start = start or (resolved_end - timedelta(days=30))
    if resolved_start > resolved_end:
        raise HTTPException(status_code=400, detail="start_date must be <= end_date")
    return resolved_start, resolved_end


def _report_filename(report_type: str, end_date: date, fmt: str) -> str:
    """Generate standardized report filename."""
    return f"SentinelIX_CVE_Report_{end_date.isoformat()}.{fmt}"


@router.get("/executive")
async def executive_report(
    profile_id: int = Query(..., ge=1),
    start_date: date | None = Query(None),
    end_date: date | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    profile = await _get_profile(db, profile_id)
    start, end = _resolve_window(start_date, end_date)
    report = await generate_executive_report(db, profile, start, end)
    return strip_internal(report)


@router.get("/technical")
async def technical_report(
    profile_id: int = Query(..., ge=1),
    start_date: date | None = Query(None),
    end_date: date | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    profile = await _get_profile(db, profile_id)
    start, end = _resolve_window(start_date, end_date)
    report = await generate_technical_report(db, profile, start, end)
    return strip_internal(report)


@router.get("/executive/export")
async def executive_report_export(
    request: Request,
    profile_id: int = Query(..., ge=1),
    start_date: date | None = Query(None),
    end_date: date | None = Query(None),
    format: Literal["csv", "xlsx", "pdf"] = Query("xlsx"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    profile = await _get_profile(db, profile_id)
    start, end = _resolve_window(start_date, end_date)
    report = await generate_executive_report(db, profile, start, end)
    report["summary"]["generated_by"] = f"{user.username} <{user.email}>"

    payload, media_type, _ = export_report_bytes(report, format, "executive")
    filename = _report_filename("executive", end, format)

    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/download")
async def report_download(
    request: Request,
    profile_id: int = Query(..., ge=1),
    start_date: date | None = Query(None),
    end_date: date | None = Query(None),
    report_type: Literal["executive", "technical"] = Query("executive"),
    format: Literal["csv", "xlsx", "pdf"] = Query("pdf"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Unified report downloader supporting executive/technical in PDF, XLSX, or CSV."""
    profile = await _get_profile(db, profile_id)
    start, end = _resolve_window(start_date, end_date)

    if report_type == "technical":
        report = await generate_technical_report(db, profile, start, end)
    else:
        report = await generate_executive_report(db, profile, start, end)

    report["summary"]["generated_by"] = f"{user.username} <{user.email}>"

    try:
        payload, media_type, _ = export_report_bytes(report, format, report_type)
    except Exception as exc:
        logger.exception("Report export failed for profile %d", profile_id)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    filename = _report_filename(report_type, end, format)

    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
