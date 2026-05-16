"""Organisation profile risk scoring engine.

Correlates the user-supplied tech stack with the CVE database by matching
vendor/product pairs against the parsed CPE data, then computes a weighted
risk score (0-100) based on severity counts.

Per-CVE `priority_score` (0–25 scale):

    priority_score = base_cvss * exploit_multiplier
                   + kev_bonus
                   + business_criticality * 0.7
                   + internet_exposure * 1.5

Where:
    base_cvss             = CVE's CVSS v3 score (0 if unscored)
    exploit_multiplier    = 1.4 if KEV-listed (actively exploited), else 1.0
    kev_bonus             = 3.0 if KEV-listed, else 0.0
    business_criticality  = 1..5 from the org profile
    internet_exposure     = 1.0 if profile.internet_exposed, else 0.0

This produces clear differentiation across CVEs:
    - 9.8 CVSS + KEV + crit-5 + exposed → 9.8*1.4 + 3 + 3.5 + 1.5 = ~21.7
    - 9.8 CVSS, no KEV, crit-3                → 9.8 + 0 + 2.1 + 0 = ~11.9
    - 5.5 CVSS, no KEV, crit-3                → 5.5 + 0 + 2.1 + 0 = ~7.6
    - unscored, KEV, crit-5                   → 0 + 3 + 3.5 + 1.5 = ~8.0
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.profile import OrgProfile, ProfileCveMatch

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 6.0,
    "MEDIUM": 2.5,
    "LOW": 1.0,
}
KEV_BONUS = 4.0  # additional weight for actively-exploited CVEs


def risk_label_for(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "NONE"


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


async def _find_matches(
    db: AsyncSession, tech_stack: list[dict[str, str | None]]
) -> list[tuple[CVE, str | None, str | None]]:
    """Return a list of (CVE, matched_vendor, matched_product) tuples."""
    if not tech_stack:
        return []

    vendors = {_normalize(e.get("vendor")) for e in tech_stack if e.get("vendor")}
    if not vendors:
        return []

    # Vendor is indexed as JSON on the CVE; use LIKE prefilter for SQLite.
    filters = [CVE.vendors.cast(_StringType()).ilike(f"%{v}%") for v in vendors] if False else []  # unused branch
    stmt = (
        select(CVE)
        .where(CVE.vendors.isnot(None))
        .order_by(CVE.cvss_v3_score.desc().nullslast())
        .limit(5000)
    )
    result = await db.execute(stmt)
    candidates = list(result.scalars().all())

    matches: list[tuple[CVE, str | None, str | None]] = []
    for cve in candidates:
        cve_vendors = {(v or "").lower() for v in (cve.vendors or [])}
        for entry in tech_stack:
            v = _normalize(entry.get("vendor"))
            p = _normalize(entry.get("product"))
            if not v:
                continue
            if v not in cve_vendors:
                continue
            # If a product is specified, require a CPE hit on (vendor, product).
            if p:
                product_hit = any(
                    _normalize(cpe.get("vendor")) == v and _normalize(cpe.get("product")) == p
                    for cpe in (cve.cpe_products or [])
                )
                if not product_hit:
                    continue
                matches.append((cve, entry.get("vendor"), entry.get("product")))
            else:
                matches.append((cve, entry.get("vendor"), None))
            break  # one match per CVE is enough for scoring
    return matches


class _StringType:  # tiny stand-in; we don't actually cast — kept for future pg move
    pass


def compute_score(cves: Iterable[CVE]) -> tuple[float, int]:
    weighted = 0.0
    count = 0
    for cve in cves:
        count += 1
        sev = (cve.cvss_v3_severity or "").upper()
        weighted += SEVERITY_WEIGHTS.get(sev, 0.0)
        if cve.is_kev:
            weighted += KEV_BONUS
    if count == 0:
        return 0.0, 0
    # Normalise: cap at 100 using a saturating scale.
    score = 100 * (1 - (1 / (1 + weighted / 20)))
    return round(min(100.0, score), 1), count


async def score_profile(db: AsyncSession, profile: OrgProfile) -> OrgProfile:
    matches = await _find_matches(db, profile.tech_stack or [])

    await db.execute(delete(ProfileCveMatch).where(ProfileCveMatch.profile_id == profile.id))
    for cve, vendor, product in matches:
        db.add(
            ProfileCveMatch(
                profile_id=profile.id,
                cve_id=cve.cve_id,
                matched_vendor=vendor,
                matched_product=product,
            )
        )

    cves_only = [c for c, _, _ in matches]
    score, count = compute_score(cves_only)
    profile.risk_score = score
    profile.risk_label = risk_label_for(score)
    profile.matched_count = count
    profile.last_scored_at = datetime.now(tz=timezone.utc)

    await db.commit()
    await db.refresh(profile)
    return profile


@dataclass
class PrioritizedCVE:
    cve: CVE
    exploit_weight: float
    priority_score: float

    @property
    def is_exploited(self) -> bool:
        return self.exploit_weight >= 1.0


def compute_priority_score(
    cve: CVE,
    business_criticality: int,
    exploited: bool | None = None,
    internet_exposed: bool = False,
) -> tuple[float, float]:
    """Return (priority_score, exploit_weight) on a 0–25 scale.

    Differentiates CVEs even when many share the same CVSS by amplifying
    actively-exploited issues and boosting the score for assets that are
    business-critical or internet-facing.
    """
    cvss = float(cve.cvss_v3_score or 0.0)
    is_exploited = exploited if exploited is not None else cve.is_kev
    exploit_weight = 1.0 if is_exploited else 0.0
    multiplier = 1.4 if is_exploited else 1.0
    kev_bonus = 3.0 if is_exploited else 0.0
    exposure_bonus = 1.5 if internet_exposed else 0.0
    score = cvss * multiplier + kev_bonus + business_criticality * 0.7 + exposure_bonus
    return round(score, 2), exploit_weight


async def get_profile_cves(
    db: AsyncSession, profile: OrgProfile, limit: int = 200
) -> list[PrioritizedCVE]:
    stmt = (
        select(CVE)
        .join(ProfileCveMatch, ProfileCveMatch.cve_id == CVE.cve_id)
        .where(ProfileCveMatch.profile_id == profile.id)
        .order_by(CVE.cvss_v3_score.desc().nullslast())
        .limit(limit)
    )
    result = await db.execute(stmt)
    cves = list(result.scalars().all())

    prioritized: list[PrioritizedCVE] = []
    for cve in cves:
        score, weight = compute_priority_score(
            cve,
            profile.business_criticality,
            internet_exposed=bool(profile.internet_exposed),
        )
        prioritized.append(PrioritizedCVE(cve=cve, exploit_weight=weight, priority_score=score))

    prioritized.sort(key=lambda p: p.priority_score, reverse=True)
    return prioritized


async def rescore_all_profiles(db: AsyncSession) -> int:
    result = await db.execute(select(OrgProfile))
    profiles = list(result.scalars().all())
    for profile in profiles:
        await score_profile(db, profile)
    return len(profiles)
