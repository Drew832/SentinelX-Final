"""Policy recommendation API schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.services.policy_ai_service import POLICY_TYPES


class PolicyRecommendRequest(BaseModel):
    profile_id: int = Field(ge=1)
    cve_id: str = Field(min_length=8, max_length=32)
    policy_type: str = Field(
        description="One of the supported SentinelIX policy focus areas.",
    )

    @field_validator("policy_type")
    @classmethod
    def known_policy(cls, v: str) -> str:
        if v not in POLICY_TYPES:
            raise ValueError(f"policy_type must be one of: {', '.join(POLICY_TYPES)}")
        return v

    @field_validator("cve_id")
    @classmethod
    def upper_cve(cls, v: str) -> str:
        return v.strip().upper()


class PolicyRecommendResponse(BaseModel):
    profile_id: int
    cve_id: str
    policy_type: str
    recommendation: str
    justification: str
    model_used: str
