"""Classify crashes by CWE and severity."""

from __future__ import annotations

CWE_MAP = {
    "heap-buffer-overflow": ("CWE-122", "Heap-based Buffer Overflow", "high"),
    "stack-buffer-overflow": ("CWE-121", "Stack-based Buffer Overflow", "high"),
    "heap-use-after-free": ("CWE-416", "Use After Free", "high"),
    "global-buffer-overflow": ("CWE-120", "Buffer Overflow", "high"),
    "stack-overflow": ("CWE-674", "Uncontrolled Recursion", "medium"),
    "null-dereference": ("CWE-476", "NULL Pointer Dereference", "medium"),
    "SEGV": ("CWE-476", "NULL Pointer Dereference", "medium"),
    "use-of-uninitialized-value": ("CWE-457", "Use of Uninitialized Variable", "medium"),
    "integer-overflow": ("CWE-190", "Integer Overflow", "high"),
    "signed-integer-overflow": ("CWE-190", "Integer Overflow", "high"),
    "shift-exponent": ("CWE-190", "Integer Overflow", "low"),
    "division-by-zero": ("CWE-369", "Divide By Zero", "low"),
    "timeout": ("CWE-835", "Loop with Unreachable Exit", "medium"),
    "out-of-memory": ("CWE-789", "Memory Allocation with Excessive Size", "medium"),
    "double-free": ("CWE-415", "Double Free", "high"),
}

EXPLOITABILITY_RULES = {
    "CWE-122": {"base_score": 8.0, "rce_potential": True},
    "CWE-121": {"base_score": 7.5, "rce_potential": True},
    "CWE-416": {"base_score": 8.5, "rce_potential": True},
    "CWE-120": {"base_score": 7.0, "rce_potential": True},
    "CWE-674": {"base_score": 5.0, "rce_potential": False},
    "CWE-476": {"base_score": 5.5, "rce_potential": False},
    "CWE-190": {"base_score": 7.0, "rce_potential": True},
    "CWE-415": {"base_score": 8.0, "rce_potential": True},
}


class CWEClassifier:
    def classify(self, crash: dict) -> dict:
        """Add CWE classification and severity to a crash report."""
        crash_type = crash.get("crash_type", "unknown")

        cwe_id = "CWE-unknown"
        cwe_name = "Unknown"
        severity = "unknown"

        for pattern, (cid, cname, sev) in CWE_MAP.items():
            if pattern.lower() in crash_type.lower():
                cwe_id = cid
                cwe_name = cname
                severity = sev
                break

        if crash_type.startswith("signal-"):
            sig = crash_type.split("-", 1)[1]
            if sig in ("SIGSEGV", "SIGBUS"):
                if cwe_id == "CWE-unknown":
                    cwe_id = "CWE-787"
                    cwe_name = "Out-of-bounds Write"
                    severity = "high"

        crash["cwe"] = cwe_id
        crash["cwe_name"] = cwe_name
        crash["severity"] = severity

        rules = EXPLOITABILITY_RULES.get(cwe_id, {})
        crash["cvss_estimate"] = rules.get("base_score", 4.0)
        crash["rce_potential"] = rules.get("rce_potential", False)

        asan = crash.get("asan_report", "")
        if asan:
            if "WRITE" in asan:
                crash["cvss_estimate"] = min(crash["cvss_estimate"] + 1.0, 10.0)
                crash["access_type"] = "WRITE"
            elif "READ" in asan:
                crash["access_type"] = "READ"

        return crash
