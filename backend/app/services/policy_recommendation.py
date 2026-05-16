"""Policy recommendation engine.

Maps a collection of CVEs to the information-security policies an organisation
should strengthen or adopt. Uses CWE identifiers, CVE description keywords, and
affected product vendors as classification signals.

Optional AI verification
------------------------
``validate_with_ai(recommendations, cves)`` is an optional second pass
that asks Claude (or the OpenAI fallback) to review the deterministic
classifier's output via :mod:`app.services.ai_gateway`. The model
returns a refined justification for every recommendation that
explicitly cites the contributing CVE evidence. When the LLM disagrees
with the rule's mapping it can downgrade the priority or mark it
incorrect, which we then drop. The deterministic output is always
returned untouched if the validation pass fails for any reason — the
engine is fail-safe, never fail-loud.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable

from app.models.cve import CVE
from app.services.ai_gateway import active_model, ai_complete, has_provider

logger = logging.getLogger(__name__)

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


# ---------------------------------------------------------------
# Optional AI verification layer
# ---------------------------------------------------------------


_AI_SYSTEM = (
    "You are SentinelX Policy Auditor, a senior security GRC analyst. You will "
    "be given a list of policy recommendations produced by a deterministic "
    "classifier alongside the contributing CVE evidence. For EACH "
    "recommendation, decide whether the mapping is accurate. Return STRICT "
    "JSON: {\"reviews\": [{\"policy_name\": str, \"verdict\": \"confirmed\" | "
    "\"weak\" | \"incorrect\", \"priority\": \"HIGH\" | \"MEDIUM\" | \"LOW\", "
    "\"justification\": str}]}. "
    "The justification MUST cite at least one concrete CVE-ID and the specific "
    "weakness or exposure that motivated the policy mapping. Keep each "
    "justification under 60 words. Never include markdown."
)


def _ai_payload(
    recommendations: list[Recommendation],
    cve_index: dict[str, CVE],
) -> dict:
    """Build the compact JSON payload the auditor model sees.

    We trim every text field aggressively so the prompt fits in a single
    Claude turn even for large recommendation sets — that's what keeps
    the /policies/recommend endpoint snappy when `ai_validate=true`.
    """
    payload: list[dict] = []
    for rec in recommendations:
        evidence_blob: list[dict] = []
        for ev in rec.evidence[:5]:
            cve = cve_index.get(ev.cve_id)
            if not cve:
                continue
            evidence_blob.append({
                "cve_id": cve.cve_id,
                "cvss": cve.cvss_v3_score,
                "severity": cve.cvss_v3_severity,
                "is_kev": bool(cve.is_kev),
                "cwe_ids": (cve.cwe_ids or [])[:5],
                "vendors": (cve.vendors or [])[:5],
                "description": (cve.description or "")[:280],
                "matched_terms": ev.matched_terms[:5],
                "match_type": ev.match_type,
            })
        payload.append({
            "policy_name": rec.policy_name,
            "engine_priority": rec.priority,
            "matched_cves": rec.matched_cves,
            "matched_terms": rec.matched_terms[:8],
            "evidence": evidence_blob,
        })
    return {"recommendations": payload}


async def validate_with_ai(
    recommendations: list[Recommendation],
    cves: Iterable[CVE],
) -> tuple[list[Recommendation], str]:
    """Have Claude verify the deterministic mapping and refine justifications.

    Returns the (possibly reordered) list of Recommendations plus a marker
    string indicating which model was used so callers can surface it in
    the UI for transparency. The deterministic output is returned
    untouched if no LLM is configured or the API call fails — this
    routine is fail-safe by design and never raises.
    """
    if not recommendations:
        return recommendations, "none"
    if not has_provider():
        return recommendations, "rules-only"

    cve_index: dict[str, CVE] = {c.cve_id: c for c in cves}
    payload = _ai_payload(recommendations, cve_index)

    result = await ai_complete(
        system=_AI_SYSTEM,
        user=json.dumps(payload),
        max_tokens=1500,
        temperature=0.2,
        timeout=30.0,
        cache_ttl=240,
        label="policy_validate",
    )
    if not result.ok:
        logger.info("Policy AI validation unavailable (%s); using rules", result.error)
        return recommendations, "rules-only"

    try:
        parsed = json.loads(result.text)
        reviews = parsed.get("reviews") or []
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.warning("Policy AI validation parse failed (%s); using rules", exc)
        return recommendations, "rules-only"

    by_name = {
        r["policy_name"]: r
        for r in reviews
        if isinstance(r, dict) and r.get("policy_name")
    }
    refined: list[Recommendation] = []
    for rec in recommendations:
        review = by_name.get(rec.policy_name)
        if not review:
            refined.append(rec)
            continue
        verdict = (review.get("verdict") or "").lower()
        if verdict == "incorrect":
            # Drop the recommendation entirely when the LLM says it's wrong.
            continue
        new_priority = (review.get("priority") or rec.priority).upper()
        if new_priority not in {"HIGH", "MEDIUM", "LOW"}:
            new_priority = rec.priority
        new_just = (review.get("justification") or "").strip() or rec.justification
        rec.priority = new_priority
        rec.justification = new_just
        refined.append(rec)

    priority_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    refined.sort(key=lambda r: (priority_rank[r.priority], -r.matched_cves))
    return refined, active_model()
