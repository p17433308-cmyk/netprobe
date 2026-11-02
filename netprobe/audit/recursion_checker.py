"""Detect unbounded recursive dissector calls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RecursionFinding:
    file_path: str
    line_number: int
    caller: str
    callee: str
    has_depth_guard: bool
    severity: str


DISSECTOR_CALL_PATTERNS = [
    re.compile(r"call_dissector(?:_with_data)?\s*\(\s*(\w+)"),
    re.compile(r"dissector_try_(?:uint|string|heuristic)\s*\("),
    re.compile(r"(\w+_handle)\s*=\s*find_dissector\s*\(\s*\"(\w+)\""),
]

DEPTH_GUARD_PATTERNS = [
    re.compile(r"(?:depth|recursion|level)\s*(?:>=?|>)\s*\d+"),
    re.compile(r"(?:MAX_RECURSION|MAX_DEPTH|RECURSION_LIMIT)"),
    re.compile(r"pinfo->(?:curr_layer_num|layer_names)"),
    re.compile(r"increment_dissection_depth\s*\("),
]


class RecursionChecker:

    def check_file(self, file_path: str | Path) -> list[RecursionFinding]:
        path = Path(file_path)
        if not path.exists():
            return []

        try:
            content = path.read_text(errors="replace")
        except Exception:
            return []

        lines = content.split("\n")
        findings = []

        current_func = "unknown"
        func_start = 0

        for i, line in enumerate(lines):
            func_match = re.match(r"^(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{?\s*$", line)
            if func_match:
                current_func = func_match.group(1)
                func_start = i

            for pat in DISSECTOR_CALL_PATTERNS:
                match = pat.search(line)
                if match:
                    context_start = max(0, func_start)
                    context_end = min(len(lines), i + 1)
                    context = "\n".join(lines[context_start:context_end])

                    has_guard = any(gp.search(context) for gp in DEPTH_GUARD_PATTERNS)

                    callee = match.group(1) if match.lastindex else "dissector"

                    if not has_guard:
                        findings.append(RecursionFinding(
                            file_path=str(path),
                            line_number=i + 1,
                            caller=current_func,
                            callee=callee,
                            has_depth_guard=False,
                            severity="high",
                        ))

        return findings

    def check_directory(self, dir_path: str | Path, glob: str = "**/*.c") -> list[RecursionFinding]:
        path = Path(dir_path)
        findings = []
        for f in path.glob(glob):
            findings.extend(self.check_file(f))
        return findings
