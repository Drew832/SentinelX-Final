"""Policy recommendation engine.

Maps a collection of CVEs to the information-security policies an organisation
should strengthen or adopt. Uses CWE identifiers, CVE description keywords, and
affected product vendors as classification signals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from app.models.cve import CVE

# ---------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------
#
# Each rule describes a single policy recommendation. If any rule's
# signal matches a CVE, the rule "fires" and the CVE contributes to
# the rule's count.


@dataclass
class PolicyRule:
    key: str
    name: str
    reason: str
    keywords: tuple[str, ...] = ()
    cwe_prefixes: tuple[str, ...] = ()
    vendor_hints: tuple[str, ...] = ()

    # runtime
    count: int = field(default=0, compare=False)
    contributing_cves: list[str] = field(default_factory=list, compare=False)


POLICY_RULES: list[PolicyRule] = [
    PolicyRule(
        key="secure_coding",
        name="Secure Coding Policy",
        reason=(
            "Multiple web-application vulnerabilities (injection, XSS, path traversal) "
            "indicate a need for enforced secure coding standards and SAST/DAST gating."
        ),
        keywords=(
            "sql injection",
            "xss",
            "cross-site scripting",
            "directory traversal",
            "path traversal",
            "command injection",
            "deserialization",
            "csrf",
            "server-side request forgery",
            "ssrf",
        ),
        cwe_prefixes=(
            "CWE-79",
            "CWE-89",
            "CWE-22",
            "CWE-77",
            "CWE-78",
            "CWE-352",
            "CWE-502",
            "CWE-918",
        ),
    ),
    PolicyRule(
        key="access_control",
        name="Access Control & Authentication Policy",
        reason=(
            "Authentication-bypass and authorisation-failure CVEs suggest weaknesses in "
            "identity controls — review MFA enforcement, least-privilege, and session management."
        ),
        keywords=(
            "authentication bypass",
            "auth bypass",
            "privilege escalation",
            "unauthenticated",
            "missing authorization",
            "broken access control",
            "session fixation",
            "credential",
            "default password",
        ),
        cwe_prefixes=("CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-269", "CWE-384"),
    ),
    PolicyRule(
        key="cryptography",
        name="Cryptography & Key Management Policy",
        reason=(
            "Weak-crypto, hardcoded-secret, or TLS-downgrade findings require cryptographic "
            "standards, rotation cadence, and key-escrow controls."
        ),
        keywords=(
            "weak cipher",
            "weak encryption",
            "hardcoded password",
            "hardcoded credential",
            "tls downgrade",
            "ssl",
            "certificate validation",
            "prng",
        ),
        cwe_prefixes=("CWE-327", "CWE-328", "CWE-330", "CWE-321", "CWE-326", "CWE-798"),
    ),
    PolicyRule(
        key="network_security",
        name="Network Security Policy",
        reason=(
            "Network-device / VPN / firewall CVEs imply perimeter risk. Tighten segmentation, "
            "VPN access reviews, and edge-device patch cadence."
        ),
        keywords=(
            "vpn",
            "firewall",
            "router",
            "switch",
            "ssl-vpn",
            "ipsec",
            "proxy",
            "dns",
        ),
        vendor_hints=(
            "cisco",
            "fortinet",
            "palo_alto",
            "juniper",
            "sonicwall",
            "checkpoint",
            "f5",
            "pulse",
            "openvpn",
        ),
    ),
    PolicyRule(
        key="patch_management",
        name="Vulnerability & Patch Management Policy",
        reason=(
            "A high volume of Critical/High CVEs means remediation SLAs and emergency-patch "
            "runbooks need formal codification and owner assignment."
        ),
    ),
    PolicyRule(
        key="incident_response",
        name="Incident Response Policy",
        reason=(
            "Actively-exploited (CISA KEV) issues increase incident likelihood — refresh IR "
            "playbooks, tabletop exercises, and on-call rotation."
        ),
    ),
    PolicyRule(
        key="data_protection",
        name="Data Protection & Privacy Policy",
        reason=(
            "Information-disclosure findings call for classification-aware logging controls, "
            "DLP, and encryption-at-rest review."
        ),
        keywords=(
            "information disclosure",
            "data leak",
            "sensitive information",
            "exposure of sensitive",
            "pii",
        ),
        cwe_prefixes=("CWE-200", "CWE-532", "CWE-538"),
    ),
    PolicyRule(
        key="supply_chain",
        name="Third-Party / Supply-Chain Security Policy",
        reason=(
            "Library / SDK / package CVEs point to supply-chain exposure — require SBOM, "
            "dependency scanning, and vendor-risk reviews."
        ),
        keywords=(
            "npm",
            "maven",
            "pypi",
            "gem",
            "composer",
            "log4j",
            "openssl",
            "dependency",
            "library",
            "package",
        ),
    ),
    PolicyRule(
        key="cloud_container",
        name="Cloud & Container Security Policy",
        reason=(
            "Container/orchestrator vulnerabilities suggest the need for hardened base images, "
            "admission controls, and cloud workload protection."
        ),
        keywords=("kubernetes", "docker", "openshift", "container escape"),
        vendor_hints=("kubernetes", "docker", "openshift", "aws", "azure", "gcp", "redhat"),
    ),
]


@dataclass
class CveEvidence:
    cve_id: str
    matched_terms: list[str]
    match_type: str  # keyword | cwe | vendor


@dataclass
class Recommendation:
    policy_name: str
    reason: str
    priority: str  # HIGH / MEDIUM / LOW
    matched_cves: int
    example_cves: list[str]
    matched_terms: list[str]  # union of every signal seen across the matched set
    evidence: list[CveEvidence]
    justification: str  # human-readable "why this CVE got mapped here"


def _match_rule(rule: PolicyRule, cve: CVE) -> tuple[bool, list[str], str | None]:
    """Return (matched, terms_hit, match_type) for this rule against `cve`."""
    haystack = (cve.description or "").lower()
    terms: list[str] = []
    match_type: str | None = None

    if rule.keywords:
        kw_hits = [k for k in rule.keywords if re.search(rf"\b{re.escape(k)}\b", haystack)]
        if kw_hits:
            terms.extend(kw_hits)
            match_type = "keyword"

    if rule.cwe_prefixes:
        cwe_hits = [
            c
            for c in (cve.cwe_ids or [])
            if c and c.startswith(rule.cwe_prefixes)
        ]
        if cwe_hits:
            terms.extend(cwe_hits)
            match_type = match_type or "cwe"

    if rule.vendor_hints:
        vendors_lower = {(v or "").lower() for v in (cve.vendors or [])}
        vendor_hits = [h for h in rule.vendor_hints if h in vendors_lower]
        if vendor_hits:
            terms.extend(vendor_hits)
            match_type = match_type or "vendor"

    return (bool(terms), terms, match_type)


def _priority_for(rule: PolicyRule, total: int) -> str:
    if total == 0:
        return "LOW"
    ratio = rule.count / total
    if rule.count >= 20 or ratio >= 0.35:
        return "HIGH"
    if rule.count >= 8 or ratio >= 0.15:
        return "MEDIUM"
    return "LOW"


def generate_policy_recommendations(cves: Iterable[CVE]) -> list[Recommendation]:
    """Map a bag of CVEs to policies that ought to be strengthened.

    Each recommendation is decorated with the actual keyword / CWE / vendor
    signals that drove the match, plus a sample of CVE-level evidence so the
    UI can explain *why* a CVE was assigned to that policy.
    """
    cve_list = list(cves)
    total = len(cve_list)

    rules = [
        PolicyRule(
            key=r.key,
            name=r.name,
            reason=r.reason,
            keywords=r.keywords,
            cwe_prefixes=r.cwe_prefixes,
            vendor_hints=r.vendor_hints,
        )
        for r in POLICY_RULES
    ]

    high_count = 0
    critical_count = 0
    exploited_count = 0

    # Per-rule evidence collection
    evidence_map: dict[str, list[CveEvidence]] = {r.key: [] for r in rules}
    terms_map: dict[str, set[str]] = {r.key: set() for r in rules}

    for cve in cve_list:
        sev = (cve.cvss_v3_severity or "").upper()
        if sev == "CRITICAL":
            critical_count += 1
        if sev == "HIGH":
            high_count += 1
        if cve.is_kev:
            exploited_count += 1
        for rule in rules:
            matched, terms, match_type = _match_rule(rule, cve)
            if not matched or not match_type:
                continue
            rule.count += 1
            terms_map[rule.key].update(terms)
            if len(rule.contributing_cves) < 8:
                rule.contributing_cves.append(cve.cve_id)
            if len(evidence_map[rule.key]) < 6:
                evidence_map[rule.key].append(
                    CveEvidence(
                        cve_id=cve.cve_id,
                        matched_terms=terms[:4],
                        match_type=match_type,
                    )
                )

    # Volume-based rules: patch management & incident response.
    patch_rule = next(r for r in rules if r.key == "patch_management")
    patch_rule.count = critical_count + high_count
    patch_contributing = [
        c
        for c in cve_list
        if (c.cvss_v3_severity or "").upper() in {"CRITICAL", "HIGH"}
    ][:8]
    patch_rule.contributing_cves = [c.cve_id for c in patch_contributing]
    evidence_map["patch_management"] = [
        CveEvidence(
            cve_id=c.cve_id,
            matched_terms=[(c.cvss_v3_severity or "HIGH").upper()],
            match_type="severity",
        )
        for c in patch_contributing[:6]
    ]
    if patch_rule.count:
        terms_map["patch_management"].update({"CRITICAL", "HIGH"})

    ir_rule = next(r for r in rules if r.key == "incident_response")
    ir_rule.count = exploited_count
    ir_contributing = [c for c in cve_list if c.is_kev][:8]
    ir_rule.contributing_cves = [c.cve_id for c in ir_contributing]
    evidence_map["incident_response"] = [
        CveEvidence(cve_id=c.cve_id, matched_terms=["CISA KEV"], match_type="kev")
        for c in ir_contributing[:6]
    ]
    if ir_rule.count:
        terms_map["incident_response"].add("CISA KEV")

    results: list[Recommendation] = []
    for rule in rules:
        if rule.count == 0:
            continue
        priority = _priority_for(rule, total)
        terms = sorted(terms_map[rule.key])[:8]
        evidence = evidence_map[rule.key]
        first = evidence[0] if evidence else None

        if first and first.match_type == "kev":
            justification = (
                f"Mapped because {rule.count} of the matched CVEs are listed in CISA KEV"
                " (active exploitation in the wild)."
            )
        elif first and first.match_type == "severity":
            justification = (
                f"Mapped because {rule.count} matched CVEs are CRITICAL or HIGH severity, "
                "driving an outsized share of the patch backlog."
            )
        elif first and first.match_type == "cwe" and terms:
            justification = (
                f"Mapped to '{rule.name}' due to weakness class match "
                f"({', '.join(terms[:3])}) on {rule.count} CVE(s)."
            )
        elif first and first.match_type == "vendor" and terms:
            justification = (
                f"Mapped because {rule.count} CVE(s) affect vendors typically "
                f"governed by this policy ({', '.join(terms[:3])})."
            )
        elif terms:
            justification = (
                f"Mapped to '{rule.name}' due to keyword match "
                f"({', '.join(terms[:3])}) in {rule.count} CVE description(s)."
            )
        else:
            justification = rule.reason

        results.append(
            Recommendation(
                policy_name=rule.name,
                reason=rule.reason,
                priority=priority,
                matched_cves=rule.count,
                example_cves=rule.contributing_cves,
                matched_terms=terms,
                evidence=evidence,
                justification=justification,
            )
        )

    priority_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    results.sort(key=lambda r: (priority_rank[r.priority], -r.matched_cves))
    return results
