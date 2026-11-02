"""Detect unchecked integer arithmetic on packet-sourced values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IntegerOverflowFinding:
    file_path: str
    line_number: int
    pattern: str
    expression: str
    severity: str


OVERFLOW_PATTERNS = [
    (r"(\w+)\s*\*\s*(\w+)\s*(?:;|\))", "unchecked_multiply", "high"),
    (r"(\w+)\s*\+\s*(\w+)\s*(?:;|\))", "unchecked_add", "medium"),
    (r"malloc\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)", "malloc_multiply", "critical"),
    (r"calloc\s*\(\s*(\w+)\s*,\s*sizeof", "calloc_attacker_count", "high"),
    (r"wmem_alloc\s*\([^,]+,\s*(\w+)\s*\*\s*", "wmem_alloc_multiply", "critical"),
    (r"g_malloc\s*\(\s*(\w+)\s*\*\s*", "gmalloc_multiply", "critical"),
    (r"\((?:guint|gint|int|unsigned)\s*\)\s*tvb_get_", "cast_truncation", "high"),
    (r"(\w+)\s*<<\s*(\w+)", "unchecked_shift", "medium"),
]


class IntegerOverflowDetector:

    def __init__(self):
        self._patterns = [(re.compile(p), name, sev) for p, name, sev in OVERFLOW_PATTERNS]

    def scan_file(self, file_path: str | Path) -> list[IntegerOverflowFinding]:
        path = Path(file_path)
        if not path.exists():
            return []

        try:
            lines = path.read_text(errors="replace").split("\n")
        except Exception:
            return []

        findings = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pat, name, severity in self._patterns:
                match = pat.search(line)
                if match:
                    findings.append(IntegerOverflowFinding(
                        file_path=str(path),
                        line_number=i + 1,
                        pattern=name,
                        expression=match.group(0).strip(),
                        severity=severity,
                    ))
        return findings

    def scan_directory(self, dir_path: str | Path, glob: str = "**/*.c") -> list[IntegerOverflowFinding]:
        path = Path(dir_path)
        findings = []
        for f in path.glob(glob):
            findings.extend(self.scan_file(f))
        findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 3))
        return findings
