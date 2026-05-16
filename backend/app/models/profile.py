"""Organisation profile + CVE match models."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Environment(str, enum.Enum):
    PROD = "PROD"
    DEV = "DEV"
    TEST = "TEST"


class OrgProfile(Base):
    __tablename__ = "org_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tech_stack: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    asset_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="profile_environment"),
        default=Environment.PROD,
        nullable=False,
    )
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    business_criticality: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_label: Mapped[str] = mapped_column(String(16), default="NONE", nullable=False)
    matched_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.utcnow(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.utcnow(),
        onupdate=lambda: datetime.utcnow(),
        nullable=False,
    )

    matches: Mapped[list["ProfileCveMatch"]] = relationship(
        back_populates="profile", cascade="all, delete-orphan"
    )


class ProfileCveMatch(Base):
    __tablename__ = "profile_cve_matches"
    __table_args__ = (UniqueConstraint("profile_id", "cve_id", name="uq_profile_cve"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("org_profiles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    matched_vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    matched_product: Mapped[str | None] = mapped_column(String(128), nullable=True)

    profile: Mapped[OrgProfile] = relationship(back_populates="matches")
