"""Asset Health categorisation service.

Groups CVEs into technology buckets (Web Servers, Databases, OS, etc.)
using keyword matching on vendor/product/description so the frontend
can render a "vulnerabilities by category" bar chart.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from app.models.cve import CVE

CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Web Servers", ("nginx", "apache", "iis", "tomcat", "haproxy", "httpd", "lighttpd")),
    ("Databases", ("mysql", "mariadb", "postgresql", "postgres", "oracle", "mongodb", "redis", "mssql", "cassandra")),
    ("Operating Systems", ("windows", "linux", "kernel", "ubuntu", "debian", "rhel", "centos", "macos", "freebsd")),
    ("Cloud / Containers", ("aws", "azure", "gcp", "docker", "kubernetes", "openshift", "ecs")),
    ("Network / VPN", ("cisco", "fortinet", "palo_alto", "juniper", "pfsense", "openvpn", "checkpoint", "f5", "sonicwall")),
    ("CMS / Collaboration", ("wordpress", "drupal", "joomla", "sharepoint", "jira", "confluence", "mediawiki")),
    ("Dev Tooling", ("gitlab", "github", "jenkins", "teamcity", "atlassian", "bitbucket", "jfrog")),
    ("Browsers & Clients", ("chrome", "firefox", "safari", "edge", "chromium", "thunderbird")),
    ("Runtime / Language", ("python", "java", "php", "golang", "ruby", "node", "dotnet", ".net", "rails")),
    ("Virtualisation", ("vmware", "vcenter", "hyperv", "xen", "virtualbox", "citrix")),
    ("Office / Productivity", ("office", "outlook", "word", "excel", "acrobat")),
]

SEVERITY_WEIGHT = {
    "CRITICAL": 8.0,
    "HIGH": 4.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
}


def _category_for(vendors: list[str], description: str | None) -> str:
    haystack = " ".join([*(vendors or []), description or ""]).lower()
    for label, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in haystack:
                return label
    return "Other"


@dataclass
class CategoryBucket:
    category: str
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    exploited: int = 0
    weighted_risk: float = 0.0
    sample_cves: list[str] = field(default_factory=list)


def compute_asset_health(cves: Iterable[CVE]) -> dict:
    buckets: dict[str, CategoryBucket] = {}

    for cve in cves:
        category = _category_for(cve.vendors or [], cve.description)
        bucket = buckets.setdefault(category, CategoryBucket(category=category))
        bucket.total += 1

        sev = (cve.cvss_v3_severity or "").upper()
        if sev == "CRITICAL":
            bucket.critical += 1
        elif sev == "HIGH":
            bucket.high += 1
        elif sev == "MEDIUM":
            bucket.medium += 1
        elif sev == "LOW":
            bucket.low += 1

        if cve.is_kev:
            bucket.exploited += 1

        bucket.weighted_risk += SEVERITY_WEIGHT.get(sev, 0.5)
        if cve.is_kev:
            bucket.weighted_risk += 3.0

        if len(bucket.sample_cves) < 5:
            bucket.sample_cves.append(cve.cve_id)

    total_cves = sum(b.total for b in buckets.values())
    categories = [
        {
            "category": b.category,
            "total": b.total,
            "critical": b.critical,
            "high": b.high,
            "medium": b.medium,
            "low": b.low,
            "exploited": b.exploited,
            "weighted_risk": round(b.weighted_risk, 1),
            "sample_cves": b.sample_cves,
        }
        for b in buckets.values()
    ]
    categories.sort(key=lambda x: x["total"], reverse=True)

    return {
        "total_cves": total_cves,
        "categories_tracked": len(categories),
        "categories": categories,
    }
