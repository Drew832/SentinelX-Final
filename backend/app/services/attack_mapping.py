"""Tiny MITRE ATT&CK mapping helpers.

This is a pragmatic mapping to enrich reports. It is intentionally minimal and
should be extended as needed.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# CWE → (ATT&CK technique id, name)
_CWE_TO_ATTACK: Dict[str, List[Tuple[str, str]]] = {
    "CWE-78": [("T1059", "Command and Scripting Interpreter")],
    "CWE-79": [("T1059.007", "JavaScript")],
    "CWE-89": [("T1190", "Exploit Public-Facing Application")],
    "CWE-22": [("T1190", "Exploit Public-Facing Application")],
    "CWE-287": [("T1078", "Valid Accounts")],
    "CWE-306": [("T1078", "Valid Accounts")],
    "CWE-352": [("T1190", "Exploit Public-Facing Application")],
    "CWE-416": [("T1068", "Exploitation for Privilege Escalation")],
    "CWE-20": [("T1190", "Exploit Public-Facing Application")],
    "CWE-94": [("T1059", "Command and Scripting Interpreter")],
}


def map_cwes_to_attack(cwe_ids: list[str]) -> list[dict]:
    out: list[dict] = []
    seen = set()
    for cwe in cwe_ids or []:
        for tid, name in _CWE_TO_ATTACK.get(cwe, []):
            key = (tid, name)
            if key in seen:
                continue
            seen.add(key)
            out.append({"technique_id": tid, "name": name, "source": cwe})
    return out

