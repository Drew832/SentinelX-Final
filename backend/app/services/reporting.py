"""Executive report generation.

Produces a structured JSON report for a profile over a date range plus
multiple export formats (CSV, Excel, PDF).
"""
from __future__ import annotations

import io
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.profile import OrgProfile, ProfileCveMatch
from app.services.risk_scoring import compute_priority_score
from app.services.epss_service import get_epss_scores
from app.services.attack_mapping import map_cwes_to_attack
from app.services.report_ai_service import generate_report_narrative

logger = logging.getLogger(__name__)


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ── Brand palette ────────────────────────────────────────────
BRAND_NAVY = "#0F1D3A"
BRAND_NAVY_LIGHT = "#1c3b7a"
BRAND_GOLD = "#E0A82E"
BRAND_GOLD_SOFT = "#F4C85A"
BRAND_BG = "#F5F6F8"
BRAND_BORDER = "#D7DDE8"
BRAND_INK = "#0F172A"
BRAND_SUBTLE = "#EEF1F7"
SEV_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#10B981",
}


@dataclass
class ReportRow:
    """A single CVE row augmented with report-specific fields."""

    cve: CVE
    priority_score: float
    exploit_weight: float

    @property
    def is_exploited(self) -> bool:
        return self.exploit_weight >= 1.0


async def _fetch_rows(
    db: AsyncSession,
    profile: OrgProfile,
    start_date: date,
    end_date: date,
) -> list[ReportRow]:
    start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
    end_dt = datetime.combine(end_date, time.max, tzinfo=timezone.utc)

    stmt = (
        select(CVE)
        .join(ProfileCveMatch, ProfileCveMatch.cve_id == CVE.cve_id)
        .where(ProfileCveMatch.profile_id == profile.id)
    )
    result = await db.execute(stmt)
    rows: list[ReportRow] = []
    for cve in result.scalars().all():
        ref_date = (
            cve.published_date
            or cve.last_modified_date
            or cve.kev_date_added
        )
        # Treat KEV stubs with no timestamp as part of the current period so
        # executive reports still reflect known-exploited exposures even
        # when NVD metadata hasn't published yet.
        if ref_date is None:
            ref_date = end_dt
        if ref_date.tzinfo is None:
            ref_date = ref_date.replace(tzinfo=timezone.utc)
        if not (start_dt <= ref_date <= end_dt):
            continue
        priority, weight = compute_priority_score(
            cve,
            profile.business_criticality,
            internet_exposed=bool(profile.internet_exposed),
        )
        rows.append(ReportRow(cve=cve, priority_score=priority, exploit_weight=weight))

    rows.sort(key=lambda r: r.priority_score, reverse=True)
    return rows


TECH_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Web Servers & Proxies", ("nginx", "apache", "iis", "tomcat", "haproxy", "httpd")),
    ("Databases", ("mysql", "mariadb", "postgresql", "oracle", "mongodb", "redis", "mssql")),
    ("Operating Systems", ("windows", "linux", "kernel", "ubuntu", "debian", "rhel", "macos")),
    ("Cloud / Containers", ("aws", "azure", "gcp", "docker", "kubernetes", "k8s", "openshift")),
    ("Network / VPN", ("cisco", "fortinet", "palo_alto", "juniper", "pfsense", "openvpn")),
    ("CMS / App Platforms", ("wordpress", "drupal", "joomla", "sharepoint", "jira", "confluence")),
    ("Dev Tooling", ("gitlab", "jenkins", "teamcity", "atlassian", "bitbucket")),
    ("Browsers / Clients", ("chrome", "firefox", "safari", "edge")),
]


def _categorize(vendors: list[str], description: str | None) -> str:
    haystack = " ".join([*(vendors or []), description or ""]).lower()
    for label, keywords in TECH_CATEGORIES:
        for kw in keywords:
            if kw in haystack:
                return label
    return "Other"


def _recommended_actions(
    severity_counts: dict[str, int],
    exploited: int,
    internet_exposed: bool,
) -> list[str]:
    actions: list[str] = []
    if exploited:
        actions.append(
            f"Patch the {exploited} actively-exploited CVE(s) before anything else — "
            "CISA KEV items historically become worm/ransomware vectors within 2 weeks."
        )
    crit = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    if crit:
        actions.append(
            f"Remediate {crit} Critical-severity findings within the next change window; "
            "apply vendor patches and treat any missing patches as audit-blocking."
        )
    if high:
        actions.append(
            f"Schedule {high} High-severity patches into the next monthly remediation cycle."
        )
    if internet_exposed:
        actions.append(
            "Asset is internet-exposed — add WAF/virtual-patch signatures for any RCE or "
            "authentication-bypass CVEs on this list while vendor patches are staged."
        )
    if not actions:
        actions.append(
            "No outstanding critical/high exposures. Maintain current patch cadence and "
            "continue to monitor the CISA KEV catalog for new additions."
        )
    return actions


def _key_observations(
    profile: OrgProfile,
    rows: list[ReportRow],
    severity_counts: dict[str, int],
    activity: list[dict[str, Any]],
    exploited: int,
) -> list[str]:
    observations: list[str] = []

    if not rows:
        observations.append(
            f"No CVEs published or modified in the selected window matched "
            f"{profile.name}'s asset inventory."
        )
        return observations

    # Highest CVSS CVE.
    highest = max(
        rows,
        key=lambda r: (r.cve.cvss_v3_score or -1),
    )
    if highest.cve.cvss_v3_score is not None:
        observations.append(
            f"Highest-severity finding: {highest.cve.cve_id} "
            f"(CVSS {highest.cve.cvss_v3_score:.1f}, {highest.cve.cvss_v3_severity or 'N/A'})."
        )

    # Exploit exposure.
    if exploited == 0:
        observations.append(
            "No CVEs in this period overlap the CISA KEV catalog — "
            "no publicly known active exploitation against this asset set."
        )
    else:
        observations.append(
            f"{exploited} CVE{'s' if exploited != 1 else ''} are actively exploited "
            "according to the CISA KEV catalog and warrant immediate remediation."
        )

    # Critical + high workload.
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
    if critical_high:
        observations.append(
            f"Remediation workload: {critical_high} Critical/High severity issues "
            f"({severity_counts.get('CRITICAL', 0)} Critical, "
            f"{severity_counts.get('HIGH', 0)} High)."
        )

    # Recent activity spikes.
    if activity:
        counts = [a["count"] for a in activity]
        avg = sum(counts) / len(counts) if counts else 0
        peak = max(activity, key=lambda a: a["count"])
        if peak["count"] >= max(avg * 2.0, 3):
            observations.append(
                f"Activity spike on {peak['date']} ({peak['count']} CVEs) — "
                "well above the period average; investigate whether a coordinated "
                "disclosure window drove the volume."
            )

    # Asset exposure context.
    if profile.internet_exposed:
        observations.append(
            f"Asset '{profile.asset_name or profile.name}' is marked internet-exposed "
            f"in {profile.environment.value}; prioritise any RCE/authentication bypass "
            "findings above all else."
        )

    return observations


async def generate_executive_report(
    db: AsyncSession,
    profile: OrgProfile,
    start_date: date,
    end_date: date,
    *,
    include_ai: bool = True,
) -> dict[str, Any]:
    rows = await _fetch_rows(db, profile, start_date, end_date)

    severity_counts: dict[str, int] = {s: 0 for s in SEVERITIES}
    vendor_counter: Counter[str] = Counter()
    daily: dict[str, int] = defaultdict(int)
    exploited = 0

    for row in rows:
        sev = (row.cve.cvss_v3_severity or "").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        for v in row.cve.vendors or []:
            vendor_counter[v] += 1
        ref_date = row.cve.published_date or row.cve.last_modified_date
        if ref_date:
            daily[ref_date.date().isoformat()] += 1
        if row.is_exploited:
            exploited += 1

    # Fill zero days so the chart has a continuous x-axis.
    activity: list[dict[str, Any]] = []
    cursor = start_date
    while cursor <= end_date:
        key = cursor.isoformat()
        activity.append({"date": key, "count": daily.get(key, 0)})
        cursor += timedelta(days=1)

    top_cves = [
        {
            "cve_id": r.cve.cve_id,
            "cvss_v3_score": r.cve.cvss_v3_score,
            "cvss_v3_severity": r.cve.cvss_v3_severity,
            "is_exploited": r.is_exploited,
            "priority_score": r.priority_score,
            "description": (r.cve.description or "")[:320],
            "vendors": r.cve.vendors or [],
            "published_date": r.cve.published_date.isoformat() if r.cve.published_date else None,
        }
        for r in rows[:10]
    ]

    priority_watchlist = [
        {
            "cve_id": r.cve.cve_id,
            "priority_score": r.priority_score,
            "cvss_v3_score": r.cve.cvss_v3_score,
            "cvss_v3_severity": r.cve.cvss_v3_severity,
            "is_exploited": r.is_exploited,
            "vendor": (r.cve.vendors or [None])[0],
            "short": (r.cve.description or "")[:160],
        }
        for r in rows[:15]
    ]

    top_vendors = [
        {"vendor": v, "count": c} for v, c in vendor_counter.most_common(10)
    ]

    top_categories_counter: Counter[str] = Counter()
    for r in rows:
        top_categories_counter[_categorize(r.cve.vendors or [], r.cve.description)] += 1
    top_categories = [
        {"category": cat, "count": cnt}
        for cat, cnt in top_categories_counter.most_common(10)
    ]

    summary = {
        "profile_id": profile.id,
        "profile_name": profile.name,
        "asset_name": profile.asset_name,
        "environment": profile.environment.value,
        "internet_exposed": profile.internet_exposed,
        "business_criticality": profile.business_criticality,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "total_cves": len(rows),
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "exploited_count": exploited,
    }

    # Top banner (used on the PDF header)
    top_banner = {
        "total_cves": len(rows),
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "kev_count": exploited,
        "tracked_groups": len(top_categories_counter),
    }

    severity_summary = {
        "buckets": [
            {"severity": s, "count": severity_counts.get(s, 0)} for s in SEVERITIES
        ],
        "total": len(rows),
        "critical_high": severity_counts.get("CRITICAL", 0)
        + severity_counts.get("HIGH", 0),
    }

    # Fast path: callers that want an instantaneous render (e.g. the
    # in-app live preview) can opt out of the AI brief and fall back
    # to the deterministic narrative builder. The downloadable PDF
    # always asks for the AI brief.
    if include_ai:
        exec_brief, exec_recs, exec_model = await generate_report_narrative(
            "executive",
            {
                "summary": summary,
                "severity_breakdown": severity_counts,
                "exposure": {
                    "exploited": exploited,
                    "non_exploited": len(rows) - exploited,
                    "internet_exposed_asset": profile.internet_exposed,
                },
                "top_vendors": top_vendors,
                "top_cves": top_cves,
                "_rows": rows,
            },
        )
    else:
        from app.services.report_ai_service import _fallback as _local_fallback
        exec_brief, exec_recs, exec_model = _local_fallback(
            exec_mode=True,
            ctx={
                "summary": summary,
                "severity_breakdown": severity_counts,
                "exposure": {
                    "exploited": exploited,
                    "non_exploited": len(rows) - exploited,
                    "internet_exposed_asset": profile.internet_exposed,
                },
            },
        )

    summary["ai_model_used"] = exec_model

    return {
        "top_banner": top_banner,
        "summary": summary,
        # Replaced by AI-driven narrative; kept for backwards compatibility (UI may still show it).
        "results_brief": (
            f"This briefing covers {len(rows)} vulnerability record(s) impacting the "
            f"{profile.name} asset group between {start_date.isoformat()} and "
            f"{end_date.isoformat()}."
        ),
        "key_observations": _key_observations(
            profile, rows, severity_counts, activity, exploited
        ),
        "severity_breakdown": severity_counts,
        "activity": activity,
        "exposure": {
            "exploited": exploited,
            "non_exploited": len(rows) - exploited,
            "internet_exposed_asset": profile.internet_exposed,
        },
        "priority_watchlist": priority_watchlist,
        "brief": exec_brief,
        "recommendations": exec_recs,
        "severity_summary": severity_summary,
        "top_cves": top_cves,
        "top_vendors": top_vendors,
        "top_categories": top_categories,
        "_rows": rows,  # internal: used by export helpers; stripped before JSON response
    }


async def generate_technical_report(
    db: AsyncSession,
    profile: OrgProfile,
    start_date: date,
    end_date: date,
    *,
    include_ai: bool = True,
) -> dict[str, Any]:
    """Technical report: full CVE table + metadata for engineering use."""
    rows = await _fetch_rows(db, profile, start_date, end_date)
    epss = await get_epss_scores([r.cve.cve_id for r in rows], limit=400)
    full = [
        {
            "cve_id": r.cve.cve_id,
            "cvss_v3_score": r.cve.cvss_v3_score,
            "cvss_v3_severity": r.cve.cvss_v3_severity,
            "cvss_v3_vector": r.cve.cvss_v3_vector,
            "cvss_v2_score": r.cve.cvss_v2_score,
            "cvss_v2_severity": r.cve.cvss_v2_severity,
            "references": r.cve.references or [],
            "is_kev": bool(r.cve.is_kev),
            "kev_vendor_project": r.cve.kev_vendor_project,
            "kev_product": r.cve.kev_product,
            "kev_vulnerability_name": r.cve.kev_vulnerability_name,
            "is_exploited": r.is_exploited,
            "epss": epss.get(r.cve.cve_id),
            "priority_score": r.priority_score,
            "vendors": r.cve.vendors or [],
            "cwe_ids": r.cve.cwe_ids or [],
            "mitre_attack": map_cwes_to_attack(r.cve.cwe_ids or []),
            "published_date": r.cve.published_date.isoformat() if r.cve.published_date else None,
            "last_modified": (
                r.cve.last_modified_date.isoformat() if r.cve.last_modified_date else None
            ),
            "description": r.cve.description or "",
        }
        for r in rows
    ]
    summary = {
        "profile_id": profile.id,
        "profile_name": profile.name,
        "asset_name": profile.asset_name,
        "environment": profile.environment.value,
        "internet_exposed": profile.internet_exposed,
        "business_criticality": profile.business_criticality,
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "total_cves": len(rows),
    }
    # Add severity metrics for template parity
    summary.update(
        {
            "critical_count": sum(1 for r in rows if (r.cve.cvss_v3_severity or "").upper() == "CRITICAL"),
            "high_count": sum(1 for r in rows if (r.cve.cvss_v3_severity or "").upper() == "HIGH"),
            "medium_count": sum(1 for r in rows if (r.cve.cvss_v3_severity or "").upper() == "MEDIUM"),
            "low_count": sum(1 for r in rows if (r.cve.cvss_v3_severity or "").upper() == "LOW"),
            "exploited_count": sum(1 for r in rows if r.is_exploited),
        }
    )

    if include_ai:
        brief, recs, model = await generate_report_narrative(
            "technical",
            {
                "summary": summary,
                "severity_breakdown": {
                    "CRITICAL": summary["critical_count"],
                    "HIGH": summary["high_count"],
                    "MEDIUM": summary["medium_count"],
                    "LOW": summary["low_count"],
                },
                "exposure": {
                    "exploited": summary["exploited_count"],
                    "non_exploited": len(rows) - summary["exploited_count"],
                    "internet_exposed_asset": profile.internet_exposed,
                },
                "top_vendors": [],
                "top_cves": full[:12],
                "_rows": rows,
            },
        )
    else:
        from app.services.report_ai_service import _fallback as _local_fallback
        brief, recs, model = _local_fallback(
            exec_mode=False,
            ctx={
                "summary": summary,
                "severity_breakdown": {
                    "CRITICAL": summary["critical_count"],
                    "HIGH": summary["high_count"],
                    "MEDIUM": summary["medium_count"],
                    "LOW": summary["low_count"],
                },
                "exposure": {
                    "exploited": summary["exploited_count"],
                    "non_exploited": len(rows) - summary["exploited_count"],
                    "internet_exposed_asset": profile.internet_exposed,
                },
            },
        )
    summary["ai_model_used"] = model
    return {"summary": summary, "cves": full, "brief": brief, "recommendations": recs, "_rows": rows}


# ============================================================
# Export helpers
# ============================================================


def _report_csv_bytes(report: dict[str, Any]) -> bytes:
    import csv

    buf = io.StringIO()
    writer = csv.writer(buf)
    s = report["summary"]
    writer.writerow(["# SentinelX Executive Report"])
    writer.writerow(["Profile", s["profile_name"]])
    writer.writerow(["Asset", s["asset_name"] or ""])
    writer.writerow(["Environment", s["environment"]])
    writer.writerow(["Internet exposed", "YES" if s["internet_exposed"] else "NO"])
    writer.writerow(["Business criticality", s["business_criticality"]])
    writer.writerow(["Window", f"{s['start_date']} → {s['end_date']}"])
    writer.writerow(["Generated at", s["generated_at"]])
    writer.writerow([])
    writer.writerow(["Total CVEs", s["total_cves"]])
    writer.writerow(["Critical", s["critical_count"]])
    writer.writerow(["High", s["high_count"]])
    writer.writerow(["Medium", s["medium_count"]])
    writer.writerow(["Low", s["low_count"]])
    writer.writerow(["Exploited (CISA KEV)", s["exploited_count"]])
    writer.writerow([])
    writer.writerow(["Key Observations"])
    for obs in report["key_observations"]:
        writer.writerow([obs])
    writer.writerow([])
    writer.writerow(
        [
            "CVE ID",
            "Severity",
            "CVSS",
            "Published",
            "Exploit Status",
            "Vendor",
            "Priority Score",
            "Description",
        ]
    )
    for row in report["_rows"]:
        c = row.cve
        writer.writerow(
            [
                c.cve_id,
                c.cvss_v3_severity or "",
                c.cvss_v3_score if c.cvss_v3_score is not None else "",
                c.published_date.isoformat() if c.published_date else "",
                "Exploited" if row.is_exploited else "Not exploited",
                ", ".join(c.vendors or []),
                row.priority_score,
                (c.description or "").replace("\n", " ").strip(),
            ]
        )
    return buf.getvalue().encode("utf-8")


def _report_xlsx_bytes(report: dict[str, Any]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()

    header_fill = PatternFill("solid", fgColor="0F1D3A")
    header_font = Font(bold=True, color="E0A82E")

    # Sheet 1: Summary
    ws = wb.active
    ws.title = "Summary"
    s = report["summary"]
    rows = [
        ("SentinelX Executive Report", ""),
        ("Profile", s["profile_name"]),
        ("Asset", s["asset_name"] or ""),
        ("Environment", s["environment"]),
        ("Internet exposed", "YES" if s["internet_exposed"] else "NO"),
        ("Business criticality", s["business_criticality"]),
        ("Window start", s["start_date"]),
        ("Window end", s["end_date"]),
        ("Generated at", s["generated_at"]),
        ("", ""),
        ("Total CVEs", s["total_cves"]),
        ("Critical", s["critical_count"]),
        ("High", s["high_count"]),
        ("Medium", s["medium_count"]),
        ("Low", s["low_count"]),
        ("Exploited (CISA KEV)", s["exploited_count"]),
        ("", ""),
        ("Key Observations", ""),
    ]
    for r in rows:
        ws.append(list(r))
    for obs in report["key_observations"]:
        ws.append(["•", obs])
    ws["A1"].font = Font(bold=True, color="FFFFFF", size=14)
    ws["A1"].fill = header_fill
    ws.merge_cells("A1:B1")
    ws["A1"].alignment = Alignment(horizontal="center")
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 80

    # Sheet 2: CVE List
    cves_ws = wb.create_sheet("CVE List")
    headers = [
        "CVE ID",
        "Severity",
        "CVSS",
        "Published",
        "Exploit Status",
        "Vendor",
        "Priority Score",
        "Description",
    ]
    cves_ws.append(headers)
    for cell in cves_ws[1]:
        cell.fill = header_fill
        cell.font = header_font
    for row in report["_rows"]:
        c = row.cve
        cves_ws.append(
            [
                c.cve_id,
                c.cvss_v3_severity or "",
                c.cvss_v3_score if c.cvss_v3_score is not None else "",
                c.published_date.isoformat() if c.published_date else "",
                "Exploited" if row.is_exploited else "Not exploited",
                ", ".join(c.vendors or []),
                row.priority_score,
                (c.description or "").replace("\n", " ").strip()[:500],
            ]
        )
    widths = [20, 12, 8, 22, 18, 32, 16, 80]
    for i, w in enumerate(widths, start=1):
        cves_ws.column_dimensions[chr(64 + i)].width = w

    # Sheet 3: Severity Breakdown
    sev_ws = wb.create_sheet("Severity Breakdown")
    sev_ws.append(["Severity", "Count"])
    for cell in sev_ws[1]:
        cell.fill = header_fill
        cell.font = header_font
    for sev, count in report["severity_breakdown"].items():
        sev_ws.append([sev, count])
    sev_ws.column_dimensions["A"].width = 16
    sev_ws.column_dimensions["B"].width = 12

    # Sheet 4: Activity
    act_ws = wb.create_sheet("Activity")
    act_ws.append(["Date", "CVE Count"])
    for cell in act_ws[1]:
        cell.fill = header_fill
        cell.font = header_font
    for row in report["activity"]:
        act_ws.append([row["date"], row["count"]])
    act_ws.column_dimensions["A"].width = 14
    act_ws.column_dimensions["B"].width = 12

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _build_radar_drawing(size: float = 120) -> "Drawing":
    """Concentric-circle radar graphic in brand gold for the cover page."""
    from reportlab.graphics.shapes import Circle, Drawing, Line, String
    from reportlab.lib import colors as rl_colors

    d = Drawing(size, size)
    cx, cy = size / 2, size / 2
    gold = rl_colors.HexColor(BRAND_GOLD)
    gold_soft = rl_colors.HexColor(BRAND_GOLD_SOFT)

    for r in (50, 38, 26, 14):
        d.add(Circle(cx, cy, r, strokeColor=gold_soft, strokeWidth=1.2,
                      fillColor=rl_colors.Color(0, 0, 0, 0)))
    d.add(Line(cx, cy - 50, cx, cy + 50, strokeColor=gold, strokeWidth=0.6))
    d.add(Line(cx - 50, cy, cx + 50, cy, strokeColor=gold, strokeWidth=0.6))
    d.add(Circle(cx, cy, 4, strokeColor=gold, fillColor=gold, strokeWidth=0))
    d.add(Circle(cx + 20, cy + 18, 3, strokeColor=gold, fillColor=gold_soft, strokeWidth=0))
    d.add(Circle(cx - 12, cy + 30, 2.5, strokeColor=gold, fillColor=gold_soft, strokeWidth=0))
    return d


def _draw_watermark(canvas, doc):
    """Diagonal CONFIDENTIAL watermark on every page."""
    from reportlab.lib import colors as rl_colors

    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 54)
    canvas.setFillColor(rl_colors.Color(0.85, 0.85, 0.85, alpha=0.18))
    canvas.translate(doc.pagesize[0] / 2, doc.pagesize[1] / 2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "CONFIDENTIAL")
    canvas.restoreState()


def _exec_header_footer(canvas, doc, report_date: str):
    """Header + footer drawn on every page of the executive report."""
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import inch

    w, h = doc.pagesize
    gold = rl_colors.HexColor(BRAND_GOLD)
    navy = rl_colors.HexColor(BRAND_NAVY)
    subtle = rl_colors.HexColor("#9CA3AF")

    canvas.saveState()

    # ── Header ──
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(navy)
    canvas.drawString(doc.leftMargin, h - 0.45 * inch,
                      "SentinelX \u2013 Intelligence Report")
    canvas.setFillColor(subtle)
    canvas.drawRightString(w - doc.rightMargin, h - 0.45 * inch, report_date)
    canvas.setStrokeColor(gold)
    canvas.setLineWidth(0.75)
    canvas.line(doc.leftMargin, h - 0.52 * inch,
                w - doc.rightMargin, h - 0.52 * inch)

    # ── Footer ──
    canvas.setStrokeColor(gold)
    canvas.setLineWidth(0.75)
    canvas.line(doc.leftMargin, 0.52 * inch,
                w - doc.rightMargin, 0.52 * inch)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(rl_colors.HexColor("#DC2626"))
    canvas.drawString(doc.leftMargin, 0.38 * inch, "CONFIDENTIAL")
    canvas.setFillColor(subtle)
    page_num = canvas.getPageNumber()
    canvas.drawRightString(w - doc.rightMargin, 0.38 * inch,
                           f"Page {page_num}")

    canvas.restoreState()
    _draw_watermark(canvas, doc)


def _severity_bar_drawing(severity_counts: dict[str, int],
                          bar_width: float = 460) -> "Drawing":
    """Horizontal stacked bar showing CRITICAL / HIGH / MEDIUM / LOW proportions."""
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors as rl_colors

    bar_height = 22
    d = Drawing(bar_width + 10, bar_height + 30)
    total = sum(severity_counts.values()) or 1
    x = 5
    label_y = bar_height + 12
    for sev in SEVERITIES:
        cnt = severity_counts.get(sev, 0)
        seg_w = max((cnt / total) * bar_width, 0)
        if seg_w < 1:
            continue
        col = rl_colors.HexColor(SEV_COLORS[sev])
        d.add(Rect(x, 0, seg_w, bar_height, fillColor=col,
                    strokeColor=rl_colors.Color(1, 1, 1, 0), strokeWidth=0))
        if seg_w > 24:
            d.add(String(x + seg_w / 2, 6, str(cnt),
                         fontSize=9, fillColor=rl_colors.white,
                         textAnchor="middle", fontName="Helvetica-Bold"))
        d.add(String(x + seg_w / 2, label_y, sev[:4],
                     fontSize=6.5, fillColor=rl_colors.HexColor(BRAND_INK),
                     textAnchor="middle", fontName="Helvetica"))
        x += seg_w
    return d


def _report_pdf_bytes(report: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.graphics.shapes import Drawing

    buf = io.BytesIO()
    s = report["summary"]
    gen_dt = s.get("generated_at", datetime.now(tz=timezone.utc).isoformat())
    report_date = gen_dt[:10]

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    usable_w = letter[0] - doc.leftMargin - doc.rightMargin

    styles = getSampleStyleSheet()

    # ── Styles ──────────────────────────────────────────────
    cover_title = ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=36,
        textColor=colors.HexColor(BRAND_NAVY), spaceAfter=2,
        fontName="Helvetica-Bold", alignment=1,
    )
    cover_tagline = ParagraphStyle(
        "CoverTagline", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor(BRAND_NAVY_LIGHT), alignment=1,
        spaceAfter=18, fontName="Helvetica",
    )
    cover_subtitle = ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"], fontSize=18,
        textColor=colors.HexColor(BRAND_GOLD), alignment=1,
        spaceAfter=6, fontName="Helvetica-Bold",
    )
    cover_meta = ParagraphStyle(
        "CoverMeta", parent=styles["Normal"], fontSize=9.5,
        textColor=colors.HexColor(BRAND_INK), alignment=1,
        leading=15,
    )
    cover_conf = ParagraphStyle(
        "CoverConf", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#DC2626"), alignment=1,
        spaceBefore=18,
    )
    section_hdr = ParagraphStyle(
        "SectionHdr", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor(BRAND_GOLD), fontName="Helvetica-Bold",
        spaceBefore=16, spaceAfter=4, borderPadding=0,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontSize=9.5,
        textColor=colors.HexColor(BRAND_INK), leading=14,
    )
    bullet_style = ParagraphStyle(
        "Bullet", parent=body_style, leftIndent=16, bulletIndent=6,
        spaceBefore=2,
    )
    small_gray = ParagraphStyle(
        "SmallGray", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#6B7280"),
    )

    # ── Helper: section header with gold underline ──────────
    def _section(title: str):
        return [
            Paragraph(title, section_hdr),
            Table(
                [[""]],
                colWidths=[usable_w],
                rowHeights=[2],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BRAND_GOLD)),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]),
            ),
            Spacer(1, 8),
        ]

    flow: list = []

    # ════════════════════════════════════════════════════════
    # 1.  COVER PAGE
    # ════════════════════════════════════════════════════════
    flow.append(Spacer(1, 1.6 * inch))

    radar = _build_radar_drawing(size=120)
    radar_table = Table([[radar]], colWidths=[usable_w])
    radar_table.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    flow.append(radar_table)
    flow.append(Spacer(1, 18))

    flow.append(Paragraph(
        f'<font color="{BRAND_NAVY}">SENTINEL</font>'
        f'<font color="{BRAND_GOLD}">IX</font>',
        cover_title,
    ))
    flow.append(Paragraph("DETECT \u00b7 PRIORITIZE \u00b7 REMEDIATE", cover_tagline))
    flow.append(Spacer(1, 10))
    flow.append(Paragraph("Intelligence Report", cover_subtitle))

    gold_rule = Table(
        [[""]],
        colWidths=[3.5 * inch],
        rowHeights=[2],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BRAND_GOLD)),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]),
    )
    gold_rule_wrapper = Table([[gold_rule]], colWidths=[usable_w])
    gold_rule_wrapper.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    flow.append(gold_rule_wrapper)
    flow.append(Spacer(1, 22))

    analyst = s.get("generated_by", "SentinelX System")
    asset_display = s.get("asset_name") or "\u2014"
    meta_lines = (
        f"<b>Organization:</b> {s['profile_name']}<br/>"
        f"<b>Asset:</b> {asset_display}<br/>"
        f"<b>Environment:</b> {s['environment']}<br/>"
        f"<b>Report Window:</b> {s['start_date']}  \u2192  {s['end_date']}<br/>"
        f"<b>Generated:</b> {gen_dt}<br/>"
        f"<b>Analyst:</b> {analyst}"
    )
    flow.append(Paragraph(meta_lines, cover_meta))
    flow.append(Paragraph("CONFIDENTIAL", cover_conf))
    flow.append(PageBreak())

    # ════════════════════════════════════════════════════════
    # 2.  EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════
    flow.extend(_section("Executive Summary"))

    sev_data = report.get("severity_breakdown", {})
    summary_headers = [
        Paragraph("<b>Total CVEs</b>", small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["CRITICAL"]}">Critical</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["HIGH"]}">High</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["MEDIUM"]}">Medium</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["LOW"]}">Low</font></b>', small_gray),
        Paragraph("<b>Exploited</b>", small_gray),
    ]
    summary_vals = [
        s["total_cves"],
        s["critical_count"],
        s["high_count"],
        s["medium_count"],
        s["low_count"],
        s["exploited_count"],
    ]
    sum_tbl = Table(
        [summary_headers, summary_vals],
        colWidths=[usable_w / 6] * 6,
    )
    sev_cell_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 1), (-1, 1), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
    ]
    sev_tints = {
        "CRITICAL": colors.Color(0.937, 0.267, 0.267, 0.09),
        "HIGH": colors.Color(0.976, 0.451, 0.086, 0.09),
        "MEDIUM": colors.Color(0.918, 0.702, 0.031, 0.09),
        "LOW": colors.Color(0.063, 0.725, 0.506, 0.09),
    }
    for col_idx, sev_key in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"], start=1):
        sev_cell_styles.append(
            ("BACKGROUND", (col_idx, 1), (col_idx, 1), sev_tints[sev_key])
        )
    sum_tbl.setStyle(TableStyle(sev_cell_styles))
    flow.append(sum_tbl)

    risk_text = (
        f"The scan identified <b>{s['total_cves']}</b> vulnerabilities across "
        f"<b>{s.get('asset_name') or s['profile_name']}</b> in the "
        f"<b>{s['environment']}</b> environment. Of these, "
        f"<b>{s['critical_count']}</b> are rated Critical and "
        f"<b>{s['exploited_count']}</b> are actively exploited per the CISA KEV catalog."
    )
    flow.append(Spacer(1, 10))
    flow.append(Paragraph(risk_text, body_style))

    # ════════════════════════════════════════════════════════
    # 3.  RISK BREAKDOWN (stacked bar)
    # ════════════════════════════════════════════════════════
    flow.extend(_section("Risk Breakdown"))

    dist_data = [
        [sev, sev_data.get(sev, 0),
         f"{(sev_data.get(sev, 0) / max(s['total_cves'], 1)) * 100:.1f}%"]
        for sev in SEVERITIES
    ]
    dist_tbl = Table(
        [["Severity", "Count", "Share"]] + dist_data,
        colWidths=[1.6 * inch, 1.0 * inch, 1.0 * inch],
    )
    dist_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F9FAFB")]),
    ]
    for row_idx, sev_key in enumerate(SEVERITIES, start=1):
        dist_styles.append(
            ("TEXTCOLOR", (0, row_idx), (0, row_idx),
             colors.HexColor(SEV_COLORS[sev_key]))
        )
    dist_tbl.setStyle(TableStyle(dist_styles))
    flow.append(dist_tbl)
    flow.append(Spacer(1, 10))
    flow.append(_severity_bar_drawing(sev_data, bar_width=usable_w - 10))

    # ════════════════════════════════════════════════════════
    # 4.  AI BRIEF
    # ════════════════════════════════════════════════════════
    brief_text = report.get("brief", "")
    if brief_text:
        flow.append(PageBreak())
        flow.extend(_section("Intelligence Brief"))
        for para in brief_text.split("\n\n"):
            para = para.strip()
            if para:
                flow.append(Paragraph(para, body_style))
                flow.append(Spacer(1, 6))

    # ════════════════════════════════════════════════════════
    # 5.  DETAILED VULNERABILITY TABLE
    # ════════════════════════════════════════════════════════
    flow.append(PageBreak())
    flow.extend(_section("Detailed Vulnerability Findings"))

    cell_style = ParagraphStyle(
        "Cell", parent=styles["Normal"], fontSize=7.5,
        textColor=colors.HexColor(BRAND_INK), leading=10,
    )
    desc_style = ParagraphStyle(
        "Desc", parent=cell_style, fontSize=7, leading=9,
    )

    vuln_headers = [
        Paragraph("<b>CVE ID</b>", cell_style),
        Paragraph("<b>CVSS</b>", cell_style),
        Paragraph("<b>Severity</b>", cell_style),
        Paragraph("<b>Published</b>", cell_style),
        Paragraph("<b>Exploit</b>", cell_style),
        Paragraph("<b>Priority</b>", cell_style),
    ]
    dash = "\u2014"
    vuln_rows_data = [vuln_headers]
    for row in report["_rows"]:
        c = row.cve
        sev_label = (c.cvss_v3_severity or "").upper()
        sev_col = SEV_COLORS.get(sev_label, BRAND_INK)
        sev_display = sev_label or dash
        cvss_display = f"{c.cvss_v3_score:.1f}" if c.cvss_v3_score is not None else dash
        pub_display = c.published_date.strftime("%Y-%m-%d") if c.published_date else dash
        vuln_rows_data.append([
            Paragraph(c.cve_id, cell_style),
            Paragraph(cvss_display, cell_style),
            Paragraph(
                f'<font color="{sev_col}"><b>{sev_display}</b></font>',
                cell_style,
            ),
            Paragraph(pub_display, cell_style),
            Paragraph(
                '<font color="#EF4444"><b>EXPLOITED</b></font>' if row.is_exploited
                else "No",
                cell_style,
            ),
            Paragraph(f"{row.priority_score:.2f}", cell_style),
        ])

    col_widths = [
        1.35 * inch, 0.55 * inch, 0.8 * inch,
        0.85 * inch, 0.85 * inch, 0.7 * inch,
    ]
    vuln_tbl = Table(vuln_rows_data, colWidths=col_widths, repeatRows=1)
    vuln_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(vuln_rows_data)):
        bg = "#F9FAFB" if i % 2 == 0 else "#FFFFFF"
        vuln_style_cmds.append(
            ("BACKGROUND", (0, i), (-1, i), colors.HexColor(bg))
        )
    vuln_tbl.setStyle(TableStyle(vuln_style_cmds))
    flow.append(vuln_tbl)

    # ════════════════════════════════════════════════════════
    # 6.  TOP VENDORS
    # ════════════════════════════════════════════════════════
    if report.get("top_vendors"):
        flow.extend([Spacer(1, 6)])
        flow.extend(_section("Top Affected Vendors"))
        v_rows = [
            [Paragraph("<b>Vendor</b>", cell_style),
             Paragraph("<b>CVE Count</b>", cell_style)]
        ] + [
            [v["vendor"], str(v["count"])] for v in report["top_vendors"]
        ]
        v_tbl = Table(v_rows, colWidths=[3.2 * inch, 1.2 * inch])
        v_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F9FAFB")]),
        ]))
        flow.append(v_tbl)

    # ════════════════════════════════════════════════════════
    # 7.  RECOMMENDATIONS
    # ════════════════════════════════════════════════════════
    recs = report.get("recommendations", [])
    if recs:
        flow.append(PageBreak())
        flow.extend(_section("Recommendations"))
        for idx, rec in enumerate(recs, 1):
            flow.append(Paragraph(f"<b>{idx}.</b>  {rec}", bullet_style))
            flow.append(Spacer(1, 4))

    # ════════════════════════════════════════════════════════
    # 8.  DIGITAL SIGNATURE BLOCK
    # ════════════════════════════════════════════════════════
    flow.append(Spacer(1, 40))
    sig_style = ParagraphStyle(
        "Sig", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor(BRAND_INK), leading=18,
    )
    flow.append(Paragraph("Report generated and approved by:", sig_style))
    flow.append(Spacer(1, 28))
    flow.append(Paragraph("____________________________", sig_style))
    flow.append(Paragraph(f"Authorized Signatory \u2014 {analyst}", sig_style))
    flow.append(Spacer(1, 10))
    flow.append(Paragraph(f"Date: {report_date}", sig_style))

    # ── Build with header / footer / watermark ─────────────
    def _on_page(canvas, doc):
        _exec_header_footer(canvas, doc, report_date)

    def _on_page_first(canvas, doc):
        _draw_watermark(canvas, doc)

    doc.build(flow, onFirstPage=_on_page_first, onLaterPages=_on_page)
    return buf.getvalue()


def _technical_xlsx_bytes(report: dict[str, Any]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = "Technical Report"

    header_fill = PatternFill("solid", fgColor="0F1D3A")
    header_font = Font(bold=True, color="E0A82E")

    s = report["summary"]
    ws.append(["SentinelX Technical Report", ""])
    ws.append(["Profile", s["profile_name"]])
    ws.append(["Asset", s["asset_name"] or ""])
    ws.append(["Environment", s["environment"]])
    ws.append(["Criticality", s["business_criticality"]])
    ws.append(["Internet exposed", "YES" if s["internet_exposed"] else "NO"])
    ws.append(["Window", f"{s['start_date']} → {s['end_date']}"])
    ws.append(["Total CVEs", s["total_cves"]])
    ws.append(["Generated", s["generated_at"]])
    ws.append([])
    ws["A1"].font = Font(bold=True, color="FFFFFF", size=14)
    ws["A1"].fill = header_fill
    ws.merge_cells("A1:B1")
    ws["A1"].alignment = Alignment(horizontal="center")

    header_row = [
        "CVE ID",
        "CVSS v3",
        "Severity",
        "CVSS v3 Vector",
        "CVSS v2",
        "Exploited",
        "Priority",
        "Vendors",
        "CWE",
        "Published",
        "Last Modified",
        "Description",
    ]
    ws.append(header_row)
    for cell in ws[ws.max_row]:
        cell.fill = header_fill
        cell.font = header_font

    for c in report["cves"]:
        ws.append(
            [
                c["cve_id"],
                c["cvss_v3_score"] if c["cvss_v3_score"] is not None else "",
                c["cvss_v3_severity"] or "",
                c["cvss_v3_vector"] or "",
                c["cvss_v2_score"] if c["cvss_v2_score"] is not None else "",
                "Exploited" if c["is_exploited"] else "Not exploited",
                c["priority_score"],
                ", ".join(c["vendors"] or []),
                ", ".join(c["cwe_ids"] or []),
                c["published_date"] or "",
                c["last_modified"] or "",
                (c["description"] or "").replace("\n", " ").strip()[:600],
            ]
        )

    widths = [18, 8, 10, 32, 8, 14, 10, 28, 16, 22, 22, 80]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[chr(64 + i)].width = w

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _tech_header_footer(canvas, doc, report_date: str):
    """Header + footer for technical report pages (landscape)."""
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import inch

    w, h = doc.pagesize
    gold = rl_colors.HexColor(BRAND_GOLD)
    navy = rl_colors.HexColor(BRAND_NAVY)
    subtle = rl_colors.HexColor("#9CA3AF")

    canvas.saveState()

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(navy)
    canvas.drawString(doc.leftMargin, h - 0.38 * inch,
                      "SentinelX \u2013 Technical Report")
    canvas.setFillColor(subtle)
    canvas.drawRightString(w - doc.rightMargin, h - 0.38 * inch, report_date)
    canvas.setStrokeColor(gold)
    canvas.setLineWidth(0.75)
    canvas.line(doc.leftMargin, h - 0.44 * inch,
                w - doc.rightMargin, h - 0.44 * inch)

    canvas.setStrokeColor(gold)
    canvas.setLineWidth(0.75)
    canvas.line(doc.leftMargin, 0.44 * inch,
                w - doc.rightMargin, 0.44 * inch)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(rl_colors.HexColor("#DC2626"))
    canvas.drawString(doc.leftMargin, 0.30 * inch, "CONFIDENTIAL")
    canvas.setFillColor(subtle)
    page_num = canvas.getPageNumber()
    canvas.drawRightString(w - doc.rightMargin, 0.30 * inch,
                           f"Page {page_num}")

    canvas.restoreState()
    _draw_watermark(canvas, doc)


def _technical_pdf_bytes(report: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    s = report["summary"]
    gen_dt = s.get("generated_at", datetime.now(tz=timezone.utc).isoformat())
    report_date = gen_dt[:10]
    page_size = landscape(letter)

    doc = SimpleDocTemplate(
        buf,
        pagesize=page_size,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.55 * inch,
    )
    usable_w = page_size[0] - doc.leftMargin - doc.rightMargin

    styles = getSampleStyleSheet()

    cover_title = ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=32,
        textColor=colors.HexColor(BRAND_NAVY), spaceAfter=2,
        fontName="Helvetica-Bold", alignment=1,
    )
    cover_tagline = ParagraphStyle(
        "CoverTagline", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor(BRAND_NAVY_LIGHT), alignment=1,
        spaceAfter=14, fontName="Helvetica",
    )
    cover_subtitle = ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"], fontSize=16,
        textColor=colors.HexColor(BRAND_GOLD), alignment=1,
        spaceAfter=6, fontName="Helvetica-Bold",
    )
    cover_meta = ParagraphStyle(
        "CoverMeta", parent=styles["Normal"], fontSize=9.5,
        textColor=colors.HexColor(BRAND_INK), alignment=1, leading=15,
    )
    cover_conf = ParagraphStyle(
        "CoverConf", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#DC2626"), alignment=1, spaceBefore=16,
    )
    section_hdr = ParagraphStyle(
        "SectionHdr", parent=styles["Heading2"], fontSize=13,
        textColor=colors.HexColor(BRAND_GOLD), fontName="Helvetica-Bold",
        spaceBefore=12, spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontSize=9,
        textColor=colors.HexColor(BRAND_INK), leading=13,
    )
    cell_style = ParagraphStyle(
        "Cell", parent=styles["Normal"], fontSize=7.5,
        textColor=colors.HexColor(BRAND_INK), leading=10,
    )
    small_gray = ParagraphStyle(
        "SmallGray", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#6B7280"),
    )

    def _section(title):
        return [
            Paragraph(title, section_hdr),
            Table(
                [[""]],
                colWidths=[usable_w],
                rowHeights=[2],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BRAND_GOLD)),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]),
            ),
            Spacer(1, 6),
        ]

    flow: list = []

    # ── Cover page ─────────────────────────────────────────
    flow.append(Spacer(1, 1.2 * inch))

    radar = _build_radar_drawing(size=110)
    radar_tbl = Table([[radar]], colWidths=[usable_w])
    radar_tbl.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    flow.append(radar_tbl)
    flow.append(Spacer(1, 14))

    flow.append(Paragraph(
        f'<font color="{BRAND_NAVY}">SENTINEL</font>'
        f'<font color="{BRAND_GOLD}">IX</font>',
        cover_title,
    ))
    flow.append(Paragraph("DETECT \u00b7 PRIORITIZE \u00b7 REMEDIATE", cover_tagline))
    flow.append(Paragraph("Technical Report", cover_subtitle))

    gold_rule = Table(
        [[""]],
        colWidths=[3.5 * inch],
        rowHeights=[2],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BRAND_GOLD)),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]),
    )
    gold_rule_wrap = Table([[gold_rule]], colWidths=[usable_w])
    gold_rule_wrap.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    flow.append(gold_rule_wrap)
    flow.append(Spacer(1, 18))

    analyst = s.get("generated_by", "SentinelX System")
    asset_display = s.get("asset_name") or "\u2014"
    meta_lines = (
        f"<b>Organization:</b> {s['profile_name']}<br/>"
        f"<b>Asset:</b> {asset_display}<br/>"
        f"<b>Environment:</b> {s['environment']}<br/>"
        f"<b>Report Window:</b> {s['start_date']}  \u2192  {s['end_date']}<br/>"
        f"<b>Generated:</b> {gen_dt}<br/>"
        f"<b>Analyst:</b> {analyst}"
    )
    flow.append(Paragraph(meta_lines, cover_meta))
    flow.append(Paragraph("CONFIDENTIAL", cover_conf))
    flow.append(PageBreak())

    # ── Summary metrics ────────────────────────────────────
    flow.extend(_section("Summary"))

    crit = s.get("critical_count", 0)
    high = s.get("high_count", 0)
    med = s.get("medium_count", 0)
    low = s.get("low_count", 0)
    exploited = s.get("exploited_count", 0)

    sum_headers = [
        Paragraph("<b>Total CVEs</b>", small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["CRITICAL"]}">Critical</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["HIGH"]}">High</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["MEDIUM"]}">Medium</font></b>', small_gray),
        Paragraph(f'<b><font color="{SEV_COLORS["LOW"]}">Low</font></b>', small_gray),
        Paragraph("<b>Exploited</b>", small_gray),
    ]
    sum_vals = [s["total_cves"], crit, high, med, low, exploited]
    sw = usable_w / 6
    sum_tbl = Table([sum_headers, sum_vals], colWidths=[sw] * 6)
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 15),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
    ]))
    flow.append(sum_tbl)
    flow.append(Spacer(1, 6))

    sev_counts = {"CRITICAL": crit, "HIGH": high, "MEDIUM": med, "LOW": low}
    flow.append(_severity_bar_drawing(sev_counts, bar_width=usable_w - 10))

    # ── AI brief ───────────────────────────────────────────
    brief_text = report.get("brief", "")
    if brief_text:
        flow.extend(_section("Intelligence Brief"))
        for para in brief_text.split("\n\n"):
            para = para.strip()
            if para:
                flow.append(Paragraph(para, body_style))
                flow.append(Spacer(1, 4))

    # ── Full CVE table ─────────────────────────────────────
    flow.append(PageBreak())
    flow.extend(_section("CVE Detail Table"))

    tbl_headers = [
        Paragraph("<b>CVE ID</b>", cell_style),
        Paragraph("<b>CVSS</b>", cell_style),
        Paragraph("<b>Severity</b>", cell_style),
        Paragraph("<b>Exploit</b>", cell_style),
        Paragraph("<b>Priority</b>", cell_style),
        Paragraph("<b>Vendor</b>", cell_style),
        Paragraph("<b>Description</b>", cell_style),
    ]
    dash = "\u2014"
    tbl_data = [tbl_headers]
    for c in report["cves"][:200]:
        sev_label = (c["cvss_v3_severity"] or "").upper()
        sev_col = SEV_COLORS.get(sev_label, BRAND_INK)
        sev_display = sev_label or dash
        cvss_display = f"{c['cvss_v3_score']:.1f}" if c["cvss_v3_score"] else dash
        vendor_display = ", ".join((c["vendors"] or [])[:2]) or dash
        tbl_data.append([
            Paragraph(c["cve_id"], cell_style),
            Paragraph(cvss_display, cell_style),
            Paragraph(
                f'<font color="{sev_col}"><b>{sev_display}</b></font>',
                cell_style,
            ),
            Paragraph(
                '<font color="#EF4444"><b>YES</b></font>' if c["is_exploited"]
                else "No",
                cell_style,
            ),
            Paragraph(f"{c['priority_score']:.2f}", cell_style),
            Paragraph(vendor_display, cell_style),
            Paragraph((c["description"] or "")[:140], cell_style),
        ])

    col_w = [
        1.3 * inch, 0.55 * inch, 0.75 * inch, 0.6 * inch,
        0.7 * inch, 1.4 * inch, usable_w - 5.3 * inch,
    ]
    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_GOLD)),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ALIGN", (1, 0), (4, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_BORDER)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(BRAND_BORDER)),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(tbl_data)):
        bg = "#F9FAFB" if i % 2 == 0 else "#FFFFFF"
        tbl_style_cmds.append(
            ("BACKGROUND", (0, i), (-1, i), colors.HexColor(bg))
        )
    tbl.setStyle(TableStyle(tbl_style_cmds))
    flow.append(tbl)

    if len(report["cves"]) > 200:
        flow.append(Spacer(1, 8))
        flow.append(Paragraph(
            f"(Showing first 200 of {len(report['cves'])} records \u2014 "
            "download XLSX for the full table.)",
            small_gray,
        ))

    # ── Recommendations ────────────────────────────────────
    recs = report.get("recommendations", [])
    if recs:
        flow.append(PageBreak())
        flow.extend(_section("Recommendations"))
        bullet_s = ParagraphStyle(
            "TBullet", parent=body_style, leftIndent=16, bulletIndent=6,
            spaceBefore=2,
        )
        for idx, rec in enumerate(recs, 1):
            flow.append(Paragraph(f"<b>{idx}.</b>  {rec}", bullet_s))
            flow.append(Spacer(1, 3))

    # ── Signature block ────────────────────────────────────
    flow.append(Spacer(1, 36))
    sig_style = ParagraphStyle(
        "Sig", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor(BRAND_INK), leading=18,
    )
    flow.append(Paragraph("Report generated and approved by:", sig_style))
    flow.append(Spacer(1, 24))
    flow.append(Paragraph("____________________________", sig_style))
    flow.append(Paragraph(f"Authorized Signatory \u2014 {analyst}", sig_style))
    flow.append(Spacer(1, 8))
    flow.append(Paragraph(f"Date: {report_date}", sig_style))

    def _on_page(canvas, doc):
        _tech_header_footer(canvas, doc, report_date)

    def _on_first(canvas, doc):
        _draw_watermark(canvas, doc)

    doc.build(flow, onFirstPage=_on_first, onLaterPages=_on_page)
    return buf.getvalue()


def _technical_csv_bytes(report: dict[str, Any]) -> bytes:
    import csv

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "CVE ID",
            "CVSS v3",
            "Severity",
            "CVSS v3 Vector",
            "CVSS v2",
            "Exploit Status",
            "Priority",
            "Vendors",
            "CWE",
            "Published",
            "Last Modified",
            "Description",
        ]
    )
    for c in report["cves"]:
        writer.writerow(
            [
                c["cve_id"],
                c["cvss_v3_score"] if c["cvss_v3_score"] is not None else "",
                c["cvss_v3_severity"] or "",
                c["cvss_v3_vector"] or "",
                c["cvss_v2_score"] if c["cvss_v2_score"] is not None else "",
                "Exploited" if c["is_exploited"] else "Not exploited",
                c["priority_score"],
                ", ".join(c["vendors"] or []),
                ", ".join(c["cwe_ids"] or []),
                c["published_date"] or "",
                c["last_modified"] or "",
                (c["description"] or "").replace("\n", " ").strip(),
            ]
        )
    return buf.getvalue().encode("utf-8")


def export_report_bytes(
    report: dict[str, Any],
    fmt: str,
    report_type: str = "executive",
) -> tuple[bytes, str, str]:
    """Return (payload, media_type, filename) for the requested format/type."""
    fmt = (fmt or "csv").lower()
    stamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    base = f"SentinelX_CVE_Report_{stamp}"

    is_technical = report_type == "technical"
    if fmt in {"xlsx", "excel"}:
        payload = _technical_xlsx_bytes(report) if is_technical else _report_xlsx_bytes(report)
        return (
            payload,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            f"{base}.xlsx",
        )
    if fmt == "pdf":
        payload = _technical_pdf_bytes(report) if is_technical else _report_pdf_bytes(report)
        return payload, "application/pdf", f"{base}.pdf"
    payload = _technical_csv_bytes(report) if is_technical else _report_csv_bytes(report)
    return payload, "text/csv", f"{base}.csv"


def strip_internal(report: dict[str, Any]) -> dict[str, Any]:
    clean = dict(report)
    clean.pop("_rows", None)
    return clean
