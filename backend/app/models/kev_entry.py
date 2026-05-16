"""Normalised CISA KEV catalog rows.

Separate from the `cves` table so the KEV catalog is authoritative even when
NVD has not published or finished enriching a CVE. Each entry is deduped by
`cve_id` (the CISA `cveID` field).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class KevEntry(Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)
    vendor_project: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    short_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    known_ransomware: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    date_added: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    source_url: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.utcnow(), nullable=False
    )
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.utcnow(),
        onupdate=lambda: datetime.utcnow(),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
