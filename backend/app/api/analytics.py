"""Analytics endpoints: policy recommendations, asset health, compliance radar, attack-surface map."""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.cve import CVE
from app.services.asset_health import compute_asset_health
from app.services.compliance import compute_compliance_radar
from app.services.policy_recommendation import generate_policy_recommendations

logger = logging.getLogger(__name__)


policies_router = APIRouter(prefix="/policies", tags=["policies"])
compliance_router = APIRouter(prefix="/compliance", tags=["compliance"])
asset_router = APIRouter(prefix="/assets", tags=["asset-health"])
geo_router = APIRouter(prefix="/cves", tags=["geo"])


async def _query_cves(
    db: AsyncSession,
    severity: Optional[str] = None,
    only_kev: bool = False,
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    limit: int = 5000,
) -> list[CVE]:
    stmt = select(CVE)
    filters = []
    if severity:
        filters.append(CVE.cvss_v3_severity == severity.upper())
    if only_kev:
        filters.append(CVE.is_kev.is_(True))
    if search:
        like = f"%{search.strip()}%"
        filters.append(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
    if vendor:
        vendor_like = f"%{vendor.strip().lower()}%"
        from sqlalchemy import String, cast, func

        filters.append(func.lower(cast(CVE.vendors, String)).like(vendor_like))
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(CVE.cvss_v3_score.desc().nullslast()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


# ---------------------------------------------------------------
# Policy recommendations
# ---------------------------------------------------------------


@policies_router.post("/recommend")
async def recommend_policies(
    body: Optional[dict] = Body(None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return policy recommendations derived from the current filter state.

    Body schema (all optional):
        { "cve_ids": [...],
          "severity": "CRITICAL",
          "only_kev": true,
          "search": "...",
          "vendor": "..." }
    """
    body = body or {}

    if body.get("cve_ids"):
        stmt = select(CVE).where(CVE.cve_id.in_(body["cve_ids"]))
        cves = list((await db.execute(stmt)).scalars().all())
    else:
        cves = await _query_cves(
            db,
            severity=body.get("severity"),
            only_kev=bool(body.get("only_kev")),
            search=body.get("search"),
            vendor=body.get("vendor"),
            limit=int(body.get("limit") or 3000),
        )

    recommendations = generate_policy_recommendations(cves)
    return {
        "total_cves_evaluated": len(cves),
        "recommendations": [
            {
                "policy_name": r.policy_name,
                "reason": r.reason,
                "justification": r.justification,
                "priority": r.priority,
                "matched_cves": r.matched_cves,
                "example_cves": r.example_cves,
                "matched_terms": r.matched_terms,
                "evidence": [
                    {
                        "cve_id": e.cve_id,
                        "matched_terms": e.matched_terms,
                        "match_type": e.match_type,
                    }
                    for e in r.evidence
                ],
            }
            for r in recommendations
        ],
    }


# ---------------------------------------------------------------
# Compliance radar (NIST CSF)
# ---------------------------------------------------------------


@compliance_router.get("/radar")
async def compliance_radar(
    db: AsyncSession = Depends(get_db),
    only_kev: bool = Query(False),
    severity: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
) -> dict:
    cves = await _query_cves(db, severity=severity, only_kev=only_kev, vendor=vendor, limit=5000)
    return compute_compliance_radar(cves)


# ---------------------------------------------------------------
# Asset health
# ---------------------------------------------------------------


@asset_router.get("/health")
async def asset_health(
    db: AsyncSession = Depends(get_db),
    only_kev: bool = Query(False),
    severity: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
) -> dict:
    cves = await _query_cves(db, severity=severity, only_kev=only_kev, vendor=vendor, limit=5000)
    return compute_asset_health(cves)


# ---------------------------------------------------------------
# Attack-surface map — Shodan per-CVE lookup
# ---------------------------------------------------------------


def _obfuscate_ip(ip: str | None) -> str:
    if not ip:
        return "0.0.0.0"
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:2] + ["x"] * max(0, len(parts) - 2))
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return f"{parts[0]}.{parts[1]}.x.x"


def _synthetic_geo(cve: CVE) -> list[dict]:
    """Deterministic, naturally-scattered geo points for the demo path."""
    import hashlib

    samples = [
        ("United States", "Ashburn", 39.0438, -77.4874, "Equinix"),
        ("United States", "San Jose", 37.3382, -121.8863, "AWS"),
        ("Germany", "Frankfurt", 50.1109, 8.6821, "Hetzner"),
        ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Leaseweb"),
        ("Singapore", "Singapore", 1.3521, 103.8198, "AWS"),
        ("Japan", "Tokyo", 35.6895, 139.6917, "NTT"),
        ("Brazil", "São Paulo", -23.5505, -46.6333, "Telefônica"),
        ("United Kingdom", "London", 51.5074, -0.1278, "BT"),
        ("Australia", "Sydney", -33.8688, 151.2093, "Telstra"),
        ("India", "Mumbai", 19.0760, 72.8777, "Reliance"),
    ]
    sev = (cve.cvss_v3_severity or "").upper()
    points: list[dict] = []
    for i, (country, city, lat, lon, org) in enumerate(samples):
        digest = hashlib.md5(f"{cve.cve_id}-{i}".encode("utf-8")).digest()
        dlat = (digest[0] - 128) / 128 * 4.0
        dlon = (digest[1] - 128) / 128 * 4.0
        points.append(
            {
                "cve_id": cve.cve_id,
                "ip_obfuscated": f"{(i * 31) % 223 + 10}.{i * 7 % 254}.x.x",
                "latitude": round(lat + dlat, 4),
                "longitude": round(lon + dlon, 4),
                "country": country,
                "city": city,
                "org": org,
                "severity": sev or "UNKNOWN",
                "cvss_v3_score": cve.cvss_v3_score,
                "is_kev": cve.is_kev,
            }
        )
    return points


@geo_router.get("/{cve_id}/geo")
async def cve_geo(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """Geo-locate affected hosts for a specific CVE via Shodan.

    Free-tier Shodan keys can't hit the `vuln:` facet, so this endpoint
    falls back to a representative geo distribution in that case and
    signals the fallback in the `source` field.
    """
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    api_key = settings.shodan_api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {
            "cve_id": cve.cve_id,
            "source": "synthetic",
            "note": "SHODAN_API_KEY not configured; showing representative geo distribution.",
            "points": _synthetic_geo(cve),
        }

    try:
        import shodan  # type: ignore
    except ImportError:  # pragma: no cover
        return {
            "cve_id": cve.cve_id,
            "source": "synthetic",
            "note": "shodan client not installed.",
            "points": _synthetic_geo(cve),
        }

    loop = asyncio.get_running_loop()
    api = shodan.Shodan(api_key)
    try:
        results = await loop.run_in_executor(
            None, lambda: api.search(f"vuln:{cve.cve_id}", limit=limit)
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Shodan geo lookup failed: %s", exc)
        return {
            "cve_id": cve.cve_id,
            "source": "synthetic",
            "note": f"Shodan unavailable ({exc}); showing representative geo distribution.",
            "points": _synthetic_geo(cve),
        }

    points: list[dict] = []
    for match in results.get("matches", [])[:limit]:
        location = match.get("location") or {}
        lat = location.get("latitude")
        lon = location.get("longitude")
        if lat is None or lon is None:
            continue
        points.append(
            {
                "cve_id": cve.cve_id,
                "ip_obfuscated": _obfuscate_ip(match.get("ip_str")),
                "latitude": float(lat),
                "longitude": float(lon),
                "country": location.get("country_name"),
                "city": location.get("city"),
                "org": match.get("org"),
                "severity": (cve.cvss_v3_severity or "").upper(),
                "cvss_v3_score": cve.cvss_v3_score,
                "is_kev": cve.is_kev,
            }
        )

    if not points:
        return {
            "cve_id": cve.cve_id,
            "source": "synthetic",
            "note": "No Shodan matches for this CVE; showing representative geo distribution.",
            "points": _synthetic_geo(cve),
        }

    return {"cve_id": cve.cve_id, "source": "shodan", "note": None, "points": points}
