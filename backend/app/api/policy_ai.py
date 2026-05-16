"""AI-assisted policy recommendations scoped to org profiles."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_user
from app.db.session import get_db
from app.models.profile import OrgProfile
from app.models.user import User
from app.schemas.policies import PolicyRecommendRequest, PolicyRecommendResponse
from app.services.policy_ai_service import POLICY_TYPES, generate_policy_recommendation

router = APIRouter(prefix="/policy-ai", tags=["policy-ai"])


async def _load_profile(db: AsyncSession, profile_id: int) -> OrgProfile:
    result = await db.execute(select(OrgProfile).where(OrgProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.get("/types", response_model=list[str])
async def list_policy_types(_: User = Depends(get_current_user)) -> list[str]:
    return list(POLICY_TYPES)


@router.post("/recommend", response_model=PolicyRecommendResponse)
async def recommend_for_cve(
    payload: PolicyRecommendRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_user),
) -> PolicyRecommendResponse:
    profile = await _load_profile(db, payload.profile_id)
    try:
        rec, why, model_used = await generate_policy_recommendation(
            db, profile, payload.cve_id, payload.policy_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return PolicyRecommendResponse(
        profile_id=profile.id,
        cve_id=payload.cve_id,
        policy_type=payload.policy_type,
        recommendation=rec,
        justification=why,
        model_used=model_used,
    )
