"""Pydantic schemas for CVE data."""
from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict


class CVEBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_severity: Optional[str] = None
    cvss_v2_vector: Optional[str] = None
    cwe_ids: Optional[List[str]] = None
    cpe_products: Optional[List[dict[str, Any]]] = None
    vendors: Optional[List[str]] = None
    references: Optional[List[str]] = None
    is_kev: bool = False
    kev_date_added: Optional[datetime] = None
    kev_vendor_project: Optional[str] = None
    kev_product: Optional[str] = None
    kev_vulnerability_name: Optional[str] = None
    kev_required_action: Optional[str] = None
    kev_due_date: Optional[datetime] = None
    kev_ransomware_use: Optional[str] = None
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None


class CVEOut(CVEBase):
    pass


class CVEListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CVEOut]


class SeverityBucket(BaseModel):
    severity: str
    count: int


class VendorBucket(BaseModel):
    vendor: str
    count: int


class TrendPoint(BaseModel):
    date: str
    count: int


class StatsResponse(BaseModel):
    total_cves: int
    kev_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unscored_count: int = 0
    categorized_total: int = 0  # Sum of critical+high+medium+low (excludes unscored)
    severity_distribution: List[SeverityBucket]
    top_vendors: List[VendorBucket]
    trend_14d: List[TrendPoint]
    trend_window_days: int = 14
    last_ingest: Optional[datetime] = None


class TelemetryPoint(BaseModel):
    cve_id: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    is_kev: bool = False
    kev_vulnerability_name: Optional[str] = None
    ip_obfuscated: str
    latitude: float
    longitude: float
    country: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None


class TelemetryResponse(BaseModel):
    generated_at: datetime
    cached: bool
    source: str = "synthetic"
    note: Optional[str] = None
    points: List[TelemetryPoint]


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = None


class ChatResponse(BaseModel):
    answer: str
    referenced_cves: List[str] = []
    intent: Optional[str] = None
    structured: Optional[dict[str, Any]] = None
