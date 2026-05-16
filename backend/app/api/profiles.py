"""Organisation profile CRUD + risk scoring API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_user
from app.db.session import get_db
from app.models.profile import OrgProfile
from app.models.user import User
from app.schemas.profile import (
    OrgProfileCreate,
    OrgProfileOut,
    OrgProfileUpdate,
    PrioritizedCVE as PrioritizedCVEOut,
    ProfileCvesResponse,
)
from app.services.export_service import profile_report_csv
from app.services.risk_scoring import get_profile_cves, score_profile

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.get("", response_model=list[OrgProfileOut])
async def list_profiles(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[OrgProfileOut]:
    result = await db.execute(select(OrgProfile).order_by(OrgProfile.name))
    return [OrgProfileOut.model_validate(p) for p in result.scalars().all()]


@router.post("", response_model=OrgProfileOut, status_code=201)
async def create_profile(
    payload: OrgProfileCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_user),
) -> OrgProfileOut:
    existing = await db.execute(select(OrgProfile).where(OrgProfile.name == payload.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Profile with this name already exists")
    profile = OrgProfile(
        name=payload.name,
        description=payload.description,
        tech_stack=[e.model_dump() for e in payload.tech_stack],
        asset_name=payload.asset_name,
        environment=payload.environment,
        internet_exposed=payload.internet_exposed,
        business_criticality=payload.business_criticality,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    await score_profile(db, profile)
    return OrgProfileOut.model_validate(profile)


@router.put("/{profile_id}", response_model=OrgProfileOut)
async def update_profile(
    profile_id: int,
    payload: OrgProfileUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_user),
) -> OrgProfileOut:
    profile = await _get(db, profile_id)
    if payload.name is not None:
        profile.name = payload.name
    if payload.description is not None:
        profile.description = payload.description
    if payload.tech_stack is not None:
        profile.tech_stack = [e.model_dump() for e in payload.tech_stack]
    if payload.asset_name is not None:
        profile.asset_name = payload.asset_name
    if payload.environment is not None:
        profile.environment = payload.environment
    if payload.internet_exposed is not None:
        profile.internet_exposed = payload.internet_exposed
    if payload.business_criticality is not None:
        profile.business_criticality = payload.business_criticality
    await db.commit()
    await db.refresh(profile)
    await score_profile(db, profile)
    return OrgProfileOut.model_validate(profile)


@router.delete("/{profile_id}")
async def delete_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_user),
) -> dict[str, str]:
    profile = await _get(db, profile_id)
    await db.delete(profile)
    await db.commit()
    return {"status": "deleted"}


@router.post("/{profile_id}/rescore", response_model=OrgProfileOut)
async def rescore_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_user),
) -> OrgProfileOut:
    profile = await _get(db, profile_id)
    await score_profile(db, profile)
    return OrgProfileOut.model_validate(profile)


@router.get("/{profile_id}/cves", response_model=ProfileCvesResponse)
async def get_profile_matched_cves(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ProfileCvesResponse:
    profile = await _get(db, profile_id)
    prioritized = await get_profile_cves(db, profile, limit=500)
    items = [
        PrioritizedCVEOut.model_validate(
            {
                **p.cve.__dict__,
                "priority_score": p.priority_score,
                "exploit_weight": p.exploit_weight,
                "is_exploited": p.is_exploited,
            }
        )
        for p in prioritized
    ]
    return ProfileCvesResponse(
        profile=OrgProfileOut.model_validate(profile),
        matched_cves=items,
        total_matches=len(items),
    )


@router.get("/{profile_id}/export")
async def export_profile_report(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    profile = await _get(db, profile_id)
    prioritized = await get_profile_cves(db, profile, limit=5000)
    csv_bytes = profile_report_csv(profile, [p.cve for p in prioritized])
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="profile-{profile.id}-report.csv"'
        },
    )


async def _get(db: AsyncSession, profile_id: int) -> OrgProfile:
    result = await db.execute(select(OrgProfile).where(OrgProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile
