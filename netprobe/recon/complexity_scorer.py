"""Score parser complexity and danger level."""

from __future__ import annotations

import re
from pathlib import Path


class ComplexityScorer:
    DANGEROUS_PATTERNS = {
        "unchecked_tvb_memcpy": {
            "pattern": r'tvb_memcpy\s*\(\s*tvb\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)',
            "weight": 9.0,
            "description": "tvb_memcpy with potentially unchecked length",
        },
        "tvb_get_string_unbounded": {
            "pattern": r'tvb_get_string_enc\s*\([^)]*\)',
            "weight": 7.0,
            "description": "String extraction that may lack length bounds",
        },
        "malloc_with_packet_size": {
            "pattern": r'(?:wmem_alloc|g_malloc|malloc)\s*\([^,]*,\s*\w+\s*\*\s*\w+\s*\)',
            "weight": 9.5,
            "description": "Memory allocation with multiplication (integer overflow risk)",
        },
        "loop_packet_bounded": {
            "pattern": r'for\s*\([^;]*;\s*\w+\s*<\s*tvb_get_\w+\s*\(',
            "weight": 8.0,
            "description": "Loop bounded by packet-supplied value",
        },
        "memcpy_packet_length": {
            "pattern": r'memcpy\s*\([^,]+,\s*[^,]+,\s*tvb_get_\w+',
            "weight": 10.0,
            "description": "memcpy with packet-derived length (heap overflow)",
        },
        "recursive_dissector": {
            "pattern": r'call_dissector\s*\(\s*\w+\s*,\s*tvb\s*,',
            "weight": 6.0,
            "description": "Recursive dissector call (stack overflow risk)",
        },
        "sscanf_usage": {
            "pattern": r'sscanf\s*\(',
            "weight": 7.5,
            "description": "sscanf usage (format string / buffer overflow)",
        },
        "sprintf_usage": {
            "pattern": r'(?:sprintf|g_snprintf)\s*\(',
            "weight": 6.5,
            "description": "sprintf/snprintf usage (potential overflow)",
        },
        "no_bounds_check_before_access": {
            "pattern": r'tvb_get_\w+\s*\(\s*tvb\s*,\s*offset\s*\)',
            "weight": 3.0,
            "description": "tvb access without explicit remaining-length check",
        },
    }

    def score_all(self, parsers: list[dict]) -> list[dict]:
        for parser in parsers:
            parser["complexity_score"] = self._score_one(parser)
            parser["danger_patterns"] = self._find_danger_patterns(parser)
        return parsers

    def _score_one(self, parser: dict) -> float:
        score = 0.0
        lines = parser.get("lines", 0)
        score += min(lines / 100, 10.0)
        score += min(parser.get("dangerous_calls", 0) / 5, 10.0)
        score += min(parser.get("loop_count", 0) * 0.5, 5.0)
        if parser.get("has_recursion"):
            score += 3.0
        if not parser.get("has_port_registration") and not parser.get("has_heuristic"):
            score += 2.0
        return min(score, 30.0)

    def _find_danger_patterns(self, parser: dict) -> list[dict]:
        findings = []
        path = Path(parser["path"])
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return findings

        for name, info in self.DANGEROUS_PATTERNS.items():
            for match in re.finditer(info["pattern"], content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "pattern_name": name,
                    "line": line_num,
                    "weight": info["weight"],
                    "description": info["description"],
                    "matched_text": match.group(0)[:100],
                })

        return findings
