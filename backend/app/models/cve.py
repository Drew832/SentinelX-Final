"""CVE ORM model."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class CVE(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_modified_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )

    cvss_v3_score: Mapped[float | None] = mapped_column(Float, index=True, nullable=True)
    cvss_v3_severity: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)

    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v2_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_v2_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)

    cwe_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    cpe_products: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    vendors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    references: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True, nullable=False)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_vendor_project: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kev_vulnerability_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(32), nullable=True)

    source_identifier: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vuln_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.utcnow(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.utcnow(),
        onupdate=lambda: datetime.utcnow(),
        nullable=False,
    )


Index("ix_cves_kev_score", CVE.is_kev, CVE.cvss_v3_score.desc())
