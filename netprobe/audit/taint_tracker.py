"""Track packet-sourced data flowing to dangerous sinks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TaintFlow:
    source_func: str
    sink_func: str
    file_path: str
    line_number: int
    variable: str
    severity: str = "medium"


TAINT_SOURCES = [
    r"tvb_get_guint(?:8|16|24|32|64)\s*\(",
    r"tvb_get_n?tohle?\s*\(",
    r"tvb_get_string_enc\s*\(",
    r"tvb_memcpy\s*\(",
    r"tvb_get_ptr\s*\(",
    r"tvb_get_bits\s*\(",
    r"tvb_reported_length\s*\(",
    r"ntohs\s*\(",
    r"ntohl\s*\(",
]

TAINT_SINKS = {
    "memory": [
        (r"malloc\s*\(", "high"),
        (r"calloc\s*\(", "high"),
        (r"realloc\s*\(", "high"),
        (r"wmem_alloc\s*\(", "high"),
        (r"g_malloc\s*\(", "high"),
        (r"memcpy\s*\([^,]+,\s*[^,]+,\s*", "critical"),
        (r"memmove\s*\([^,]+,\s*[^,]+,\s*", "high"),
        (r"tvb_memcpy\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*", "critical"),
    ],
    "loop": [
        (r"for\s*\([^;]*;\s*\w+\s*<\s*", "high"),
        (r"while\s*\(\s*\w+\s*<\s*", "high"),
    ],
    "format": [
        (r"printf\s*\(", "critical"),
        (r"snprintf\s*\(", "medium"),
        (r"fprintf\s*\(", "medium"),
    ],
    "index": [
        (r"\[\s*\w+\s*\]", "high"),
    ],
}


class TaintTracker:
    """Lightweight intraprocedural taint tracking for C parser source."""

    def __init__(self):
        self._source_patterns = [re.compile(p) for p in TAINT_SOURCES]
        self._sink_patterns = {}
        for category, patterns in TAINT_SINKS.items():
            self._sink_patterns[category] = [(re.compile(p), sev) for p, sev in patterns]

    def analyze_file(self, file_path: str | Path) -> list[TaintFlow]:
        path = Path(file_path)
        if not path.exists():
            return []

        try:
            content = path.read_text(errors="replace")
        except Exception:
            return []

        flows = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            for src_pat in self._source_patterns:
                if src_pat.search(line):
                    var_match = re.search(r"(\w+)\s*=\s*" + src_pat.pattern, line)
                    variable = var_match.group(1) if var_match else "unknown"

                    window = lines[max(0, i):min(len(lines), i + 30)]
                    for window_idx, wline in enumerate(window):
                        for category, sink_pats in self._sink_patterns.items():
                            for sink_pat, severity in sink_pats:
                                if sink_pat.search(wline) and (variable in wline or window_idx == 0):
                                    flows.append(TaintFlow(
                                        source_func=src_pat.pattern.split("\\s")[0].replace("\\", ""),
                                        sink_func=sink_pat.pattern.split("\\s")[0].replace("\\", ""),
                                        file_path=str(path),
                                        line_number=i + window_idx + 1,
                                        variable=variable,
                                        severity=severity,
                                    ))
        return flows

    def analyze_directory(self, dir_path: str | Path, glob: str = "**/*.c") -> list[TaintFlow]:
        path = Path(dir_path)
        flows = []
        for f in path.glob(glob):
            flows.extend(self.analyze_file(f))
        flows.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 3))
        return flows
