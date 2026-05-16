"""NIST Cybersecurity Framework (CSF) compliance & audit radar.

Maps every CVE to one of the five NIST CSF functions (Identify / Protect /
Detect / Respond / Recover) using CWE category signals. Emits a radar-chart
shaped score where a *higher* score means "better posture", i.e. fewer
weighted vulnerabilities in that function.
"""
from __future__ import annotations

from typing import Iterable

from app.models.cve import CVE

# Approximate CWE → CSF function mapping used by NIST NVD analysts.
CSF_FUNCTIONS = ("Identify", "Protect", "Detect", "Respond", "Recover")

CSF_RULES: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    # (function, cwe prefixes, keywords)
    (
        "Protect",
        (
            "CWE-287",
            "CWE-306",
            "CWE-862",
            "CWE-863",
            "CWE-269",
            "CWE-79",
            "CWE-89",
            "CWE-22",
            "CWE-78",
            "CWE-77",
            "CWE-502",
            "CWE-352",
            "CWE-918",
            "CWE-327",
            "CWE-326",
            "CWE-321",
            "CWE-798",
        ),
        ("authentication", "authorization", "encryption", "tls", "xss", "injection"),
    ),
    (
        "Identify",
        ("CWE-200", "CWE-798", "CWE-532", "CWE-538"),
        ("asset inventory", "exposed", "information disclosure", "sensitive"),
    ),
    (
        "Detect",
        ("CWE-532", "CWE-778", "CWE-223"),
        ("logging", "monitoring", "detect", "audit"),
    ),
    (
        "Respond",
        ("CWE-400", "CWE-404"),
        ("denial of service", "dos", "resource exhaustion", "crash"),
    ),
    (
        "Recover",
        ("CWE-494", "CWE-693"),
        ("backup", "restore", "recovery", "supply chain"),
    ),
]


SEVERITY_WEIGHT = {
    "CRITICAL": 8.0,
    "HIGH": 4.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
}
KEV_BONUS = 3.0


def _classify(cve: CVE) -> str:
    haystack = (cve.description or "").lower()
    cwes = set((cve.cwe_ids or []))
    for func, cwe_prefixes, keywords in CSF_RULES:
        if any(any(c.startswith(p) for p in cwe_prefixes) for c in cwes):
            return func
        if any(k in haystack for k in keywords):
            return func
    # Default: treat as "Protect" since most CVEs concern preventive controls.
    return "Protect"


def compute_compliance_radar(cves: Iterable[CVE]) -> dict:
    """Compute a per-function weighted risk + defender score.

    Each function score is in [0, 100] where 100 means "no material exposure".
    """
    cve_list = list(cves)
    per_function: dict[str, dict[str, float]] = {
        f: {"weighted_risk": 0.0, "cve_count": 0, "critical": 0, "high": 0, "exploited": 0}
        for f in CSF_FUNCTIONS
    }
    breakdown_cves: dict[str, list[dict]] = {f: [] for f in CSF_FUNCTIONS}

    for cve in cve_list:
        func = _classify(cve)
        slot = per_function[func]
        sev = (cve.cvss_v3_severity or "").upper()
        weight = SEVERITY_WEIGHT.get(sev, 0.5)
        if cve.is_kev:
            weight += KEV_BONUS
        slot["weighted_risk"] += weight
        slot["cve_count"] += 1
        if sev == "CRITICAL":
            slot["critical"] += 1
        elif sev == "HIGH":
            slot["high"] += 1
        if cve.is_kev:
            slot["exploited"] += 1
        if len(breakdown_cves[func]) < 5:
            breakdown_cves[func].append(
                {
                    "cve_id": cve.cve_id,
                    "severity": cve.cvss_v3_severity,
                    "is_kev": cve.is_kev,
                }
            )

    scores = []
    for f in CSF_FUNCTIONS:
        risk = per_function[f]["weighted_risk"]
        # Saturating inverse so score ≈ 100 at risk=0 and asymptotes toward 0 for big risks.
        score = 100 * (1 / (1 + risk / 25))
        scores.append(
            {
                "function": f,
                "score": round(score, 1),
                "risk": round(risk, 1),
                "cve_count": per_function[f]["cve_count"],
                "critical": per_function[f]["critical"],
                "high": per_function[f]["high"],
                "exploited": per_function[f]["exploited"],
                "sample_cves": breakdown_cves[f],
            }
        )

    overall = round(sum(s["score"] for s in scores) / len(scores), 1) if scores else 0.0
    return {
        "overall_score": overall,
        "total_cves": len(cve_list),
        "per_function": scores,
    }
