"""AI-generated security policy recommendations tied to a profile CVE."""
from __future__ import annotations

import logging
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.cve import CVE
from app.models.profile import OrgProfile
from app.services.risk_scoring import get_profile_cves

logger = logging.getLogger(__name__)

POLICY_TYPES = (
    "Access Control",
    "Network Security",
    "Data Protection",
    "Incident Response",
    "Application Security",
    "Physical & Supply Chain Security",
)


def _cve_payload(cve: CVE) -> dict[str, Any]:
    return {
        "cve_id": cve.cve_id,
        "description": (cve.description or "")[:2000],
        "cvss_v3_score": cve.cvss_v3_score,
        "cvss_v3_severity": cve.cvss_v3_severity,
        "is_kev": cve.is_kev,
        "cwe_ids": cve.cwe_ids or [],
        "vendors": (cve.vendors or [])[:12],
        "kev_vulnerability_name": cve.kev_vulnerability_name,
    }


def _local_recommendation(policy_type: str, cve: CVE, profile: OrgProfile) -> tuple[str, str]:
    """Deterministic fallback when no LLM key is configured."""
    desc = (cve.description or "").lower()
    why_bits: list[str] = []
    if cve.is_kev:
        why_bits.append("it appears on the CISA Known Exploited Vulnerabilities catalog (confirmed in-the-wild exploitation)")
    if cve.cwe_ids:
        why_bits.append(f"CWE identifiers {', '.join(cve.cwe_ids[:5])} anchor the weakness class")
    if "auth" in desc or "credential" in desc or "password" in desc:
        why_bits.append("the description references authentication or credentials")
    if "remote" in desc or "network" in desc or "rce" in desc:
        why_bits.append("language in the CVE narrative points to network-exposed or remote attack paths")
    if not why_bits:
        why_bits.append("the CVE metadata and severity signal organizational risk that should be governed under policy")

    justification = (
        f"Mapped to “{policy_type}” because {'; '.join(why_bits)}. "
        f"This aligns the finding with how your {profile.name} stack consumes the affected technology."
    )

    rec = (
        f"For {policy_type}: treat {cve.cve_id} as a tracked remediation item. "
        "Validate exposure on assets tied to this profile, apply vendor mitigations or compensating controls, "
        "and document owner, due date, and verification evidence in your GRC workflow."
    )
    return rec, justification


async def _call_openai_policy(
    policy_type: str,
    profile: OrgProfile,
    cve_block: str,
) -> str:
    if not settings.openai_api_key:
        raise RuntimeError("openai key missing")
    system = (
        "You are a senior information security architect. Produce a concise policy recommendation "
        "for the customer's environment. You MUST include two labeled sections exactly as follows:\n"
        "RECOMMENDATION: (actionable guidance)\n"
        "WHY_THIS_MAPS: (2–4 sentences explaining why this CVE belongs under the selected policy type, "
        "citing concrete phrases, CWEs, KEV status, or exposure — not generic filler).\n"
        "Keep total length under 450 words."
    )
    user = (
        f"Organisation profile: {profile.name}\n"
        f"Tech stack (JSON): {profile.tech_stack}\n"
        f"Selected policy focus: {policy_type}\n"
        f"CVE context:\n{cve_block}\n"
    )
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.openai_model,
                "temperature": 0.25,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


async def _call_anthropic_policy(
    policy_type: str,
    profile: OrgProfile,
    cve_block: str,
) -> str:
    if not settings.anthropic_api_key:
        raise RuntimeError("anthropic key missing")
    system = (
        "You are a senior information security architect. Output exactly two labeled sections:\n"
        "RECOMMENDATION:\n"
        "WHY_THIS_MAPS:\n"
        "The WHY section must explain, with specific references to the CVE text, CWEs, KEV status, or exposure, "
        "why the issue belongs under the selected policy type."
    )
    user = (
        f"Organisation profile: {profile.name}\n"
        f"Tech stack: {profile.tech_stack}\n"
        f"Policy type: {policy_type}\n"
        f"CVE:\n{cve_block}\n"
    )
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": settings.anthropic_model,
                "max_tokens": 900,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
    parts = data.get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


def _split_llm_text(text: str) -> tuple[str, str]:
    upper = text.upper()
    rec_key = "RECOMMENDATION:"
    why_key = "WHY_THIS_MAPS:"
    if rec_key in upper and why_key in upper:
        # Case-insensitive split
        lower = text
        i_rec = lower.lower().find(rec_key.lower())
        i_why = lower.lower().find(why_key.lower())
        if i_rec < i_why:
            rec = lower[i_rec + len(rec_key) : i_why].strip()
            why = lower[i_why + len(why_key) :].strip()
        else:
            why = lower[i_why + len(why_key) : i_rec].strip()
            rec = lower[i_rec + len(rec_key) :].strip()
        return rec, why
    return text.strip(), ""


async def generate_policy_recommendation(
    db: AsyncSession,
    profile: OrgProfile,
    cve_id: str,
    policy_type: str,
) -> tuple[str, str, str]:
    """
    Returns (recommendation, justification, model_used).
    """
    if policy_type not in POLICY_TYPES:
        raise ValueError(f"policy_type must be one of: {', '.join(POLICY_TYPES)}")

    cve_row = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = cve_row.scalar_one_or_none()
    if not cve:
        raise ValueError("CVE not found")

    matched = await get_profile_cves(db, profile, limit=5000)
    matched_ids = {c.cve_id for c in matched}
    if cve.cve_id not in matched_ids:
        raise ValueError("Selected CVE is not part of this profile's matched technology stack")

    payload = _cve_payload(cve)
    cve_block = "\n".join(f"{k}: {v}" for k, v in payload.items())

    model_used = "local-rules"
    try:
        raw: str | None = None
        if settings.anthropic_api_key:
            raw = await _call_anthropic_policy(policy_type, profile, cve_block)
            model_used = settings.anthropic_model
        elif settings.openai_api_key:
            raw = await _call_openai_policy(policy_type, profile, cve_block)
            model_used = settings.openai_model
        else:
            raise RuntimeError("no llm")
        rec, why = _split_llm_text(raw)
        if not why:
            rec2, why2 = _local_recommendation(policy_type, cve, profile)
            return (rec or rec2), why2, f"{model_used}+filled-why"
        return rec, why, model_used
    except Exception as exc:  # noqa: BLE001
        logger.warning("Policy LLM generation failed, using local fallback: %s", exc)
        rec_l, why_l = _local_recommendation(policy_type, cve, profile)
        return rec_l, why_l, "local-fallback"
