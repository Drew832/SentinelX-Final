"""Schemas for organisation profiles + risk scoring."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.profile import Environment
from app.schemas.cve import CVEOut


class TechStackEntry(BaseModel):
    vendor: str = Field(min_length=1, max_length=128)
    product: Optional[str] = None
    version: Optional[str] = None


class OrgProfileBase(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    description: Optional[str] = None
    tech_stack: List[TechStackEntry] = Field(default_factory=list)
    asset_name: Optional[str] = None
    environment: Environment = Environment.PROD
    internet_exposed: bool = False
    business_criticality: int = Field(default=3, ge=1, le=5)


class OrgProfileCreate(OrgProfileBase):
    pass


class OrgProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tech_stack: Optional[List[TechStackEntry]] = None
    asset_name: Optional[str] = None
    environment: Optional[Environment] = None
    internet_exposed: Optional[bool] = None
    business_criticality: Optional[int] = Field(default=None, ge=1, le=5)


class OrgProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str] = None
    tech_stack: List[TechStackEntry]
    asset_name: Optional[str] = None
    environment: Environment
    internet_exposed: bool
    business_criticality: int
    risk_score: float
    risk_label: str
    matched_count: int
    last_scored_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class PrioritizedCVE(CVEOut):
    priority_score: float
    exploit_weight: float
    is_exploited: bool


class ProfileCvesResponse(BaseModel):
    profile: OrgProfileOut
    matched_cves: List[PrioritizedCVE]
    total_matches: int
