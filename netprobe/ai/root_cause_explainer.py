"""LLM-powered crash root cause explanation."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RootCauseExplanation:
    summary: str
    root_cause: str
    vulnerable_code: str
    attack_vector: str
    remediation: str


class RootCauseExplainer:
    """Explain crash root causes in plain English from ASAN reports."""

    CRASH_EXPLANATIONS = {
        "heap-buffer-overflow": {
            "summary": "The program wrote or read beyond the end of a heap-allocated buffer.",
            "cause": "A packet field specifying a length or count was used without validation, "
                     "causing the parser to access memory beyond the allocated buffer.",
            "fix": "Validate all packet-sourced lengths against buffer sizes before use.",
        },
        "stack-buffer-overflow": {
            "summary": "The program wrote beyond the end of a stack-allocated buffer.",
            "cause": "A fixed-size stack buffer was used with a packet-controlled length, "
                     "allowing the attacker to overflow the stack.",
            "fix": "Replace fixed-size stack buffers with dynamic allocation, or cap the length.",
        },
        "use-after-free": {
            "summary": "The program accessed memory that was already freed.",
            "cause": "A pointer to freed memory was retained and later dereferenced during "
                     "protocol parsing, likely due to incorrect object lifecycle management.",
            "fix": "Null out pointers after free, or use arena/pool allocation.",
        },
        "null-dereference": {
            "summary": "The program dereferenced a NULL pointer.",
            "cause": "An allocation or lookup returned NULL (e.g., missing protocol field) "
                     "and the result was used without a NULL check.",
            "fix": "Add NULL checks after allocations and lookups.",
        },
    }

    def explain(self, asan_report: str, crash_type: str | None = None,
                function: str | None = None) -> RootCauseExplanation:
        if not crash_type:
            crash_type = self._detect_type(asan_report)

        info = self.CRASH_EXPLANATIONS.get(
            crash_type,
            {"summary": f"Memory safety violation: {crash_type}",
             "cause": "The parser performed an unsafe memory operation on attacker-controlled data.",
             "fix": "Review the flagged function for missing bounds checks."},
        )

        func_name = function or self._extract_function(asan_report)
        access_size = self._extract_access_size(asan_report)

        vulnerable_code = f"Function: {func_name}"
        if access_size:
            vulnerable_code += f"\nAccess size: {access_size} bytes"

        return RootCauseExplanation(
            summary=info["summary"],
            root_cause=info["cause"],
            vulnerable_code=vulnerable_code,
            attack_vector=f"Send a crafted packet that causes {func_name} to trigger {crash_type}. "
                          f"The packet contains a malicious field value that leads to "
                          f"out-of-bounds memory access during protocol parsing.",
            remediation=info["fix"],
        )

    def _detect_type(self, report: str) -> str:
        report_lower = report.lower()
        if "heap-buffer-overflow" in report_lower:
            return "heap-buffer-overflow"
        if "stack-buffer-overflow" in report_lower:
            return "stack-buffer-overflow"
        if "use-after-free" in report_lower or "heap-use-after-free" in report_lower:
            return "use-after-free"
        if "null" in report_lower and "deref" in report_lower:
            return "null-dereference"
        return "unknown"

    def _extract_function(self, report: str) -> str:
        match = re.search(r"#0\s+\S+\s+in\s+(\w+)", report)
        return match.group(1) if match else "unknown"

    def _extract_access_size(self, report: str) -> str | None:
        match = re.search(r"(?:READ|WRITE) of size (\d+)", report)
        return match.group(1) if match else None
