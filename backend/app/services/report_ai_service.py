"""LLM-backed briefings and recommendations for Intelligence Reports."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def _compact_report_context(report: dict[str, Any], max_cves: int = 12) -> dict[str, Any]:
    top = report.get("top_cves") or []
    rows = report.get("_rows") or []
    if rows and not top:
        # technical report path
        top = [
            {
                "cve_id": r.cve.cve_id,
                "cvss_v3_score": r.cve.cvss_v3_score,
                "cvss_v3_severity": r.cve.cvss_v3_severity,
                "is_kev": bool(getattr(r.cve, "is_kev", False)),
                "vendors": r.cve.vendors or [],
                "cwe_ids": r.cve.cwe_ids or [],
                "description": (r.cve.description or "")[:300],
            }
            for r in rows[:max_cves]
        ]
    return {
        "summary": report.get("summary", {}),
        "severity_breakdown": report.get("severity_breakdown", {}),
        "exposure": report.get("exposure", {}),
        "top_vendors": report.get("top_vendors", [])[:8],
        "top_cves": top[:max_cves],
    }


async def _call_openai(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=75.0) as client:
        resp = await client.post(
            f"{settings.openai_base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.openai_model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


async def _call_anthropic(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=75.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": settings.anthropic_model,
                "max_tokens": 1100,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
    parts = data.get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


def _fallback(exec_mode: bool, ctx: dict[str, Any]) -> tuple[str, list[str], str]:
    s = ctx.get("summary", {})
    sev = ctx.get("severity_breakdown", {})
    exp = ctx.get("exposure", {})
    kev = int(exp.get("exploited") or 0)
    crit_high = int(sev.get("CRITICAL", 0) or 0) + int(sev.get("HIGH", 0) or 0)
    brief = (
        f"SentinelX analysed {s.get('total_cves', 0)} CVEs for {s.get('profile_name', 'this profile')} "
        f"from {s.get('start_date')} to {s.get('end_date')}. "
        f"Exposure includes {kev} KEV-flagged items and {crit_high} Critical/High findings."
    )
    recs = [
        "Patch or mitigate KEV-flagged vulnerabilities first; validate exposure on internet-facing assets.",
        "Prioritize Critical and High CVEs by owner and due date; require remediation evidence (ticket + validation).",
        "For systems that cannot be patched quickly, apply compensating controls (WAF rules, segmentation, disable vulnerable features).",
    ]
    if exec_mode:
        recs.insert(0, "Assign an executive sponsor and track remediation progress weekly until KEV exposure is cleared.")
    return brief, recs, "local-fallback"


async def generate_report_narrative(
    report_type: str,
    report: dict[str, Any],
    compliance_framework: Optional[str] = None,
) -> tuple[str, List[str], str]:
    """Returns (brief, recommendations[], model_used)."""
    ctx = _compact_report_context(report)
    exec_mode = report_type == "executive"
    system = (
        "You are SentinelX, a senior cyber threat intelligence analyst. "
        "You MUST NOT use placeholder or generic remediation. "
        "You MUST tailor output to the provided CVE context, including CVSS, KEV, vendors, CWE, "
        "internet exposure, and the chosen compliance framework. "
        "Return STRICTLY valid JSON with keys: brief (string), recommendations (array of strings). "
        "No markdown, no extra keys."
    )
    user = {
        "audience": "executive leadership" if exec_mode else "SOC analysts and security engineers",
        "report_type": report_type,
        "compliance_framework": compliance_framework,
        "context": ctx,
        "requirements": {
            "include": [
                "KEV/CVSS/EPSS context when available",
                "affected infrastructure / stack implications",
                "prioritization logic",
                "patching/mitigation strategy",
                "compliance/security recommendations",
            ],
            "style": "enterprise SOC intelligence briefing; concise; high signal",
        },
    }

    try:
        raw: Optional[str] = None
        model = "local-fallback"
        if settings.anthropic_api_key:
            raw = await _call_anthropic(system, str(user))
            model = settings.anthropic_model
        elif settings.openai_api_key:
            raw = await _call_openai(system, str(user))
            model = settings.openai_model
        else:
            raise RuntimeError("no llm configured")

        import json

        parsed = json.loads(raw)
        brief = str(parsed.get("brief") or "").strip()
        recs = parsed.get("recommendations") or []
        recs = [str(r).strip() for r in recs if str(r).strip()]
        if not brief or not recs:
            raise ValueError("LLM returned empty narrative")
        return brief, recs[:10], model
    except Exception as exc:  # noqa: BLE001
        logger.warning("Report narrative generation failed, using fallback: %s", exc)
        brief, recs, model = _fallback(exec_mode=exec_mode, ctx=ctx)
        return brief, recs, model

