"""Threat telemetry endpoint backed by Shodan."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.cve import TelemetryResponse
from app.services.shodan_service import get_shodan_service

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("", response_model=TelemetryResponse)
async def telemetry(db: AsyncSession = Depends(get_db)) -> TelemetryResponse:
    service = get_shodan_service()
    return await service.get_telemetry(db)
