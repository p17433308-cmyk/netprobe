"""Audit recently changed code via git diff for regressions."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DiffFinding:
    file_path: str
    line_number: int
    change_type: str
    dangerous_pattern: str
    commit: str | None = None
    severity: str = "medium"


DANGEROUS_IN_DIFF = [
    (r"memcpy\s*\(", "unbounded_memcpy", "high"),
    (r"malloc\s*\(\s*\w+\s*\*", "unchecked_malloc_multiply", "critical"),
    (r"tvb_memcpy\s*\(", "tvb_memcpy_added", "high"),
    (r"tvb_get_string_enc\s*\(", "unbounded_string", "medium"),
    (r"sprintf\s*\(", "sprintf_usage", "high"),
    (r"strcpy\s*\(", "strcpy_usage", "high"),
    (r"strcat\s*\(", "strcat_usage", "high"),
    (r"gets\s*\(", "gets_usage", "critical"),
    (r"for\s*\([^;]*;\s*\w+\s*<\s*tvb_get", "packet_bounded_loop", "high"),
]


class DiffAuditor:

    def __init__(self):
        self._patterns = [(re.compile(p), name, sev) for p, name, sev in DANGEROUS_IN_DIFF]

    def audit_diff(self, repo_path: str | Path, base: str = "HEAD~10",
                   file_glob: str = "*.c") -> list[DiffFinding]:
        repo = Path(repo_path)
        try:
            result = subprocess.run(
                ["git", "diff", base, "--unified=0", "--", file_glob],
                cwd=repo, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return []
        except Exception:
            return []

        return self._parse_diff(result.stdout)

    def audit_commit(self, repo_path: str | Path, commit: str) -> list[DiffFinding]:
        repo = Path(repo_path)
        try:
            result = subprocess.run(
                ["git", "show", commit, "--unified=0", "--format="],
                cwd=repo, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return []
        except Exception:
            return []

        findings = self._parse_diff(result.stdout)
        for f in findings:
            f.commit = commit
        return findings

    def _parse_diff(self, diff_text: str) -> list[DiffFinding]:
        findings = []
        current_file = None
        current_line = 0

        for line in diff_text.split("\n"):
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("@@ "):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1))
            elif line.startswith("+") and not line.startswith("+++"):
                added_code = line[1:]
                for pat, name, severity in self._patterns:
                    if pat.search(added_code):
                        findings.append(DiffFinding(
                            file_path=current_file or "unknown",
                            line_number=current_line,
                            change_type="added",
                            dangerous_pattern=name,
                            severity=severity,
                        ))
                current_line += 1

        return findings
