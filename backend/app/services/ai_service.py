"""AI security chat assistant.

The query handler classifies user intent and routes to the right database
slice (CVE-by-id, vendor lookup, severity rollup, asset profile, count,
KEV listing). Response shape varies by intent so the frontend can render a
focused card for a CVE, a table for a vendor, a number for a count, etc.

When `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set we still produce a
natural-language answer via the LLM, but the structured payload is filled
locally so the frontend stays fast and useful even offline.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.cve import CVE
from app.models.profile import OrgProfile
from app.schemas.cve import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SEVERITY_PATTERN = re.compile(r"\b(critical|high|medium|low)\b", re.IGNORECASE)
VENDOR_HINTS = (
    "microsoft", "cisco", "apache", "oracle", "google", "fortinet", "vmware",
    "redhat", "ubuntu", "linux", "wordpress", "drupal", "nginx", "openssl",
    "atlassian", "jenkins", "gitlab", "kubernetes", "docker", "ivanti",
    "palo_alto", "paloalto", "juniper", "f5", "ibm", "adobe", "apple",
)
COUNT_TRIGGERS = ("how many", "count of", "total of", "number of")
RECENT_TRIGGERS = ("recent", "latest", "newest", "this week", "last 7 days", "last week")
EXPLOIT_TRIGGERS = ("exploited", "kev", "actively exploited", "ransomware")


SYSTEM_PROMPT = (
    "You are SentinelX, a senior cyber threat intelligence analyst. "
    "Answer questions about vulnerabilities concisely and accurately, using "
    "the provided CVE context whenever relevant. Cite CVE IDs you reference. "
    "If the context is empty, say so honestly."
)


# ============================================================
# Intent detection
# ============================================================


def classify_intent(message: str) -> Tuple[str, Dict[str, Any]]:
    """Return (intent, slots).

    Intents:
        cve_lookup     — user mentioned at least one CVE-ID
        count          — "how many CVEs are critical?"
        severity       — "show me critical CVEs"
        vendor         — vendor / product question
        asset_profile  — asks about a specific org profile / asset
        kev            — actively-exploited / ransomware / KEV
        recent         — "what are the latest CVEs?"
        general        — fallback
    """
    text = message.strip()
    lower = text.lower()
    slots: Dict[str, Any] = {}

    cve_ids = [c.upper() for c in CVE_PATTERN.findall(text)]
    if cve_ids:
        slots["cve_ids"] = cve_ids
        return "cve_lookup", slots

    if any(t in lower for t in COUNT_TRIGGERS):
        sev_match = SEVERITY_PATTERN.search(lower)
        if sev_match:
            slots["severity"] = sev_match.group(1).upper()
        if any(k in lower for k in EXPLOIT_TRIGGERS):
            slots["only_kev"] = True
        return "count", slots

    if any(k in lower for k in EXPLOIT_TRIGGERS):
        return "kev", slots

    sev_match = SEVERITY_PATTERN.search(lower)
    if sev_match and ("cve" in lower or "vulnerab" in lower):
        slots["severity"] = sev_match.group(1).upper()
        return "severity", slots

    for hint in VENDOR_HINTS:
        if hint in lower:
            slots["vendor"] = hint
            return "vendor", slots

    # Asset / profile question: e.g. "what about my prod gateway"
    if "asset" in lower or "profile" in lower or "stack" in lower:
        slots["query"] = text
        return "asset_profile", slots

    if any(k in lower for k in RECENT_TRIGGERS):
        return "recent", slots

    return "general", slots


# ============================================================
# Data fetchers per intent
# ============================================================


async def _by_ids(db: AsyncSession, ids: List[str]) -> List[CVE]:
    if not ids:
        return []
    result = await db.execute(select(CVE).where(CVE.cve_id.in_(ids)))
    return list(result.scalars().all())


async def _count_query(db: AsyncSession, slots: Dict[str, Any]) -> Dict[str, Any]:
    stmt = select(func.count(CVE.cve_id))
    filters = []
    if slots.get("severity"):
        filters.append(CVE.cvss_v3_severity == slots["severity"])
    if slots.get("only_kev"):
        filters.append(CVE.is_kev.is_(True))
    if filters:
        stmt = stmt.where(and_(*filters))
    total = (await db.execute(stmt)).scalar_one()
    return {"total": total, **slots}


async def _by_severity(db: AsyncSession, sev: str, limit: int = 8) -> List[CVE]:
    stmt = (
        select(CVE)
        .where(CVE.cvss_v3_severity == sev.upper())
        .order_by(CVE.published_date.desc().nullslast())
        .limit(limit)
    )
    return list((await db.execute(stmt)).scalars().all())


async def _by_vendor(db: AsyncSession, vendor: str, limit: int = 8) -> List[CVE]:
    """Vendor-bias search.

    JSON filtering is dialect-sensitive (SQLite/Postgres differ), so we widen
    the SQL to a description ILIKE then refine in Python against the parsed
    `vendors` list. Falls back to description matches when no vendor row hits.
    """
    stmt = (
        select(CVE)
        .where(CVE.description.ilike(f"%{vendor}%"))
        .order_by(CVE.cvss_v3_score.desc().nullslast())
        .limit(limit * 4)
    )
    cves = list((await db.execute(stmt)).scalars().all())
    needle = vendor.lower()
    refined = [
        c
        for c in cves
        if any(needle in (v or "").lower() for v in (c.vendors or []))
    ]
    return (refined or cves)[:limit]


async def _kev_recent(db: AsyncSession, limit: int = 8) -> List[CVE]:
    stmt = (
        select(CVE)
        .where(CVE.is_kev.is_(True))
        .order_by(CVE.kev_date_added.desc().nullslast(), CVE.cvss_v3_score.desc().nullslast())
        .limit(limit)
    )
    return list((await db.execute(stmt)).scalars().all())


async def _recent(db: AsyncSession, limit: int = 8) -> List[CVE]:
    stmt = (
        select(CVE)
        .order_by(CVE.published_date.desc().nullslast())
        .limit(limit)
    )
    return list((await db.execute(stmt)).scalars().all())


async def _asset_profile(db: AsyncSession, query: str) -> Optional[OrgProfile]:
    like = f"%{query.lower()}%"
    stmt = select(OrgProfile).where(
        or_(
            func.lower(OrgProfile.name).like(like),
            func.lower(OrgProfile.asset_name).like(like),
        )
    ).limit(1)
    return (await db.execute(stmt)).scalar_one_or_none()


# ============================================================
# Response shaping
# ============================================================


def _summarize_cve(cve: CVE) -> Dict[str, Any]:
    return {
        "cve_id": cve.cve_id,
        "description": (cve.description or "")[:600],
        "cvss_v3_score": cve.cvss_v3_score,
        "cvss_v3_severity": cve.cvss_v3_severity,
        "is_kev": cve.is_kev,
        "kev_vulnerability_name": cve.kev_vulnerability_name,
        "vendors": (cve.vendors or [])[:6],
        "cwe_ids": cve.cwe_ids or [],
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
    }


def _format_cve_lookup(cves: List[CVE]) -> str:
    if not cves:
        return (
            "I don't have those CVE IDs in the database yet — they may be too "
            "new for the last NVD ingest, or the IDs may be misspelled."
        )
    lines = []
    for c in cves:
        sev = c.cvss_v3_severity or "N/A"
        score = c.cvss_v3_score if c.cvss_v3_score is not None else "—"
        kev = " · CISA KEV (actively exploited)" if c.is_kev else ""
        lines.append(f"**{c.cve_id}** — {sev} (CVSS {score}){kev}")
        if c.description:
            lines.append(c.description[:500])
        if c.vendors:
            lines.append(f"_Affected vendors: {', '.join(c.vendors[:6])}_")
        if c.cwe_ids:
            lines.append(f"_CWE: {', '.join(c.cwe_ids[:6])}_")
        lines.append("")
    return "\n".join(lines).strip()


def _format_count(slots: Dict[str, Any]) -> str:
    sev = slots.get("severity")
    only_kev = slots.get("only_kev")
    total = slots.get("total", 0)
    qualifier = []
    if sev:
        qualifier.append(sev.title())
    if only_kev:
        qualifier.append("CISA KEV")
    label = " ".join(qualifier) or "tracked"
    return (
        f"**{total:,}** {label} CVE(s) currently sit in the SentinelX database. "
        "Use the CVE Explorer to drill into the list, or ask me about a specific CVE ID."
    )


def _format_severity_list(sev: str, cves: List[CVE]) -> str:
    if not cves:
        return f"No {sev.title()}-severity CVEs in the database for the active filters."
    lines = [f"**Top {len(cves)} {sev.title()}-severity CVEs (most recent first):**", ""]
    for c in cves:
        score = c.cvss_v3_score or "—"
        flag = " ⚡" if c.is_kev else ""
        lines.append(f"- {c.cve_id} — CVSS {score}{flag} — {(c.description or '')[:140]}")
    return "\n".join(lines)


def _format_vendor(vendor: str, cves: List[CVE]) -> str:
    if not cves:
        return (
            f"I don't see any CVEs in the database that mention **{vendor}** in their "
            "description or affected-vendor list. Try a more specific product name."
        )
    lines = [f"**Top {vendor.title()} CVEs by CVSS:**", ""]
    for c in cves:
        sev = c.cvss_v3_severity or "—"
        score = c.cvss_v3_score or "—"
        kev = " ⚡ KEV" if c.is_kev else ""
        lines.append(
            f"- {c.cve_id} — {sev} (CVSS {score}){kev}: {(c.description or '')[:160]}"
        )
    return "\n".join(lines)


def _format_kev(cves: List[CVE]) -> str:
    if not cves:
        return "No CVEs are currently flagged as actively exploited in the database."
    lines = ["**Most recent CISA KEV (actively exploited) entries:**", ""]
    for c in cves:
        added = c.kev_date_added.date().isoformat() if c.kev_date_added else "—"
        ransom = " · ransomware-linked" if (c.kev_ransomware_use or "").lower() == "known" else ""
        lines.append(
            f"- **{c.cve_id}** ({added}){ransom} — "
            f"{c.kev_vulnerability_name or (c.description or '')[:140]}"
        )
    return "\n".join(lines)


def _format_recent(cves: List[CVE]) -> str:
    if not cves:
        return "No CVEs published recently. Try triggering a fresh NVD ingest."
    lines = ["**Most recently published CVEs:**", ""]
    for c in cves:
        date = c.published_date.date().isoformat() if c.published_date else "—"
        sev = c.cvss_v3_severity or "—"
        lines.append(
            f"- {c.cve_id} ({date}) — {sev} — {(c.description or '')[:160]}"
        )
    return "\n".join(lines)


def _format_asset_profile(profile: Optional[OrgProfile], query: str) -> str:
    if profile is None:
        return (
            f"I couldn't find an organisation profile matching **{query.strip()}**. "
            "Create one from the Org Profiles page so the assistant can scope answers to "
            "the assets you care about."
        )
    return (
        f"**Profile:** {profile.name}\n"
        f"**Asset:** {profile.asset_name or '—'}\n"
        f"**Environment:** {profile.environment.value} · "
        f"Internet-exposed: {'yes' if profile.internet_exposed else 'no'} · "
        f"Criticality: {profile.business_criticality}/5\n"
        f"**Risk score:** {profile.risk_score:.1f} ({profile.risk_label}) — "
        f"{profile.matched_count} matched CVE(s)."
    )


# ============================================================
# Top-level dispatch
# ============================================================


async def _structured_answer(
    db: AsyncSession, message: str
) -> Tuple[str, str, Dict[str, Any], List[Dict[str, Any]]]:
    """Run the matching intent handler. Returns (intent, answer, structured, context)."""
    intent, slots = classify_intent(message)

    if intent == "cve_lookup":
        cves = await _by_ids(db, slots["cve_ids"])
        return (
            intent,
            _format_cve_lookup(cves),
            {"intent": intent, "ids": slots["cve_ids"], "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )

    if intent == "count":
        slots = await _count_query(db, slots)
        return (
            intent,
            _format_count(slots),
            {"intent": intent, **slots},
            [],
        )

    if intent == "severity":
        sev = slots["severity"]
        cves = await _by_severity(db, sev)
        return (
            intent,
            _format_severity_list(sev, cves),
            {"intent": intent, "severity": sev, "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )

    if intent == "vendor":
        vendor = slots["vendor"]
        cves = await _by_vendor(db, vendor)
        return (
            intent,
            _format_vendor(vendor, cves),
            {"intent": intent, "vendor": vendor, "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )

    if intent == "kev":
        cves = await _kev_recent(db)
        return (
            intent,
            _format_kev(cves),
            {"intent": intent, "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )

    if intent == "recent":
        cves = await _recent(db)
        return (
            intent,
            _format_recent(cves),
            {"intent": intent, "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )

    if intent == "asset_profile":
        profile = await _asset_profile(db, slots.get("query") or message)
        return (
            intent,
            _format_asset_profile(profile, slots.get("query") or message),
            {
                "intent": intent,
                "profile": (
                    {
                        "id": profile.id,
                        "name": profile.name,
                        "asset_name": profile.asset_name,
                        "environment": profile.environment.value,
                        "internet_exposed": profile.internet_exposed,
                        "business_criticality": profile.business_criticality,
                        "risk_score": profile.risk_score,
                        "risk_label": profile.risk_label,
                        "matched_count": profile.matched_count,
                    }
                    if profile
                    else None
                ),
            },
            [],
        )

    # general — fall back to a recent KEV summary so we still feel useful.
    cves = await _kev_recent(db, limit=5)
    if cves:
        return (
            "general",
            _format_kev(cves),
            {"intent": "general", "cves": [_summarize_cve(c) for c in cves]},
            [_summarize_cve(c) for c in cves],
        )
    return (
        "general",
        "Ask me a specific question — by CVE ID (e.g. CVE-2024-1234), vendor, "
        "severity, or asset profile name.",
        {"intent": "general"},
        [],
    )


async def _call_anthropic(message: str, context: List[Dict[str, Any]], history: List[Dict[str, str]]) -> str:
    if not settings.anthropic_api_key:
        raise RuntimeError("anthropic key missing")

    context_text = "\n\n".join(
        f"- {c['cve_id']} (CVSS {c.get('cvss_v3_score')} {c.get('cvss_v3_severity')}, KEV={c.get('is_kev')}): {c.get('description', '')}"
        for c in context
    ) or "No matching CVEs in local database."

    messages = list(history)
    messages.append({"role": "user", "content": message})

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
                "max_tokens": 1024,
                "system": f"{SYSTEM_PROMPT}\n\nLocal CVE context:\n{context_text}",
                "messages": messages,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    parts = data.get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


async def _call_openai(message: str, context: List[Dict[str, Any]], history: List[Dict[str, str]]) -> str:
    if not settings.openai_api_key:
        raise RuntimeError("openai key missing")

    context_text = "\n\n".join(
        f"- {c['cve_id']} (CVSS {c.get('cvss_v3_score')} {c.get('cvss_v3_severity')}, KEV={c.get('is_kev')}): {c.get('description', '')}"
        for c in context
    ) or "No matching CVEs in local database."

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": f"Local CVE context:\n{context_text}"},
    ]
    messages.extend(history)
    messages.append({"role": "user", "content": message})

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.openai_model,
                "messages": messages,
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


async def answer_question(db: AsyncSession, payload: ChatRequest) -> ChatResponse:
    intent, local_answer, structured, context = await _structured_answer(db, payload.message)
    history = [
        {"role": m.role, "content": m.content}
        for m in (payload.history or [])
        if m.role in {"user", "assistant"}
    ][-8:]

    answer = local_answer
    try:
        if settings.anthropic_api_key:
            answer = await _call_anthropic(payload.message, context, history)
        elif settings.openai_api_key:
            answer = await _call_openai(payload.message, context, history)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM call failed, using local answer: %s", exc)
        answer = local_answer

    referenced = [c["cve_id"] for c in context if c.get("cve_id")]
    return ChatResponse(
        answer=answer,
        referenced_cves=referenced,
        intent=intent,
        structured=structured,
    )
