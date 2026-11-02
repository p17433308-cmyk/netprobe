"""Static pattern scanner for dangerous code in parsers."""

from __future__ import annotations

import re
from pathlib import Path


VULNERABILITY_PATTERNS = [
    {
        "name": "unchecked_memcpy",
        "pattern": r'(?:memcpy|tvb_memcpy)\s*\([^,]+,\s*[^,]+,\s*(?:tvb_get_\w+|len|length|size|count)\b',
        "severity_score": 9.5,
        "cwe": "CWE-122",
        "description": "memcpy/tvb_memcpy with packet-derived length — potential heap overflow",
    },
    {
        "name": "malloc_integer_overflow",
        "pattern": r'(?:wmem_alloc|g_malloc|g_new|malloc)\s*\([^)]*\b\w+\s*\*\s*\w+',
        "severity_score": 9.0,
        "cwe": "CWE-190",
        "description": "Memory allocation with multiplication — integer overflow risk",
    },
    {
        "name": "packet_bounded_loop",
        "pattern": r'for\s*\([^;]*;\s*\w+\s*<\s*(?:tvb_get_\w+|num_|count|len)',
        "severity_score": 8.0,
        "cwe": "CWE-834",
        "description": "Loop bounded by packet-supplied value without sanity cap",
    },
    {
        "name": "unbounded_string_copy",
        "pattern": r'tvb_get_string_enc\s*\(\s*(?:wmem_packet_scope|pinfo->pool)',
        "severity_score": 7.0,
        "cwe": "CWE-120",
        "description": "String extraction from packet — potential unbounded allocation",
    },
    {
        "name": "recursive_dissector_call",
        "pattern": r'call_dissector\s*\(\s*\w+_handle\s*,\s*(?:next_tvb|tvb)\s*,',
        "severity_score": 6.5,
        "cwe": "CWE-674",
        "description": "Recursive dissector call — stack overflow risk without depth limit",
    },
    {
        "name": "sprintf_packet_data",
        "pattern": r'(?:sprintf|g_snprintf)\s*\([^,]+,\s*[^,]*(?:tvb_|val_)',
        "severity_score": 7.5,
        "cwe": "CWE-134",
        "description": "sprintf/snprintf with packet-derived data — format string risk",
    },
    {
        "name": "sscanf_usage",
        "pattern": r'sscanf\s*\([^,]+,\s*"[^"]*%[^"]*s',
        "severity_score": 8.0,
        "cwe": "CWE-120",
        "description": "sscanf with %s — potential buffer overflow",
    },
    {
        "name": "unchecked_tvb_offset",
        "pattern": r'tvb_get_(?:guint|gint)\w+\s*\(\s*tvb\s*,\s*offset\s*\)',
        "severity_score": 3.0,
        "cwe": "CWE-125",
        "description": "tvb access without explicit remaining-length check",
    },
    {
        "name": "while_true_loop",
        "pattern": r'while\s*\(\s*(?:TRUE|1|true)\s*\)',
        "severity_score": 5.0,
        "cwe": "CWE-835",
        "description": "Infinite loop pattern — potential hang if break condition fails",
    },
    {
        "name": "raw_pointer_arithmetic",
        "pattern": r'(?:guint8|char)\s*\*\s*\w+\s*=\s*(?:tvb_get_ptr|ep_alloc)',
        "severity_score": 6.0,
        "cwe": "CWE-119",
        "description": "Raw pointer from tvb_get_ptr — memory safety depends on manual checks",
    },
    {
        "name": "no_remaining_check",
        "pattern": r'offset\s*\+=.*?\n(?!.*tvb_reported_length_remaining)',
        "severity_score": 4.0,
        "cwe": "CWE-125",
        "description": "Offset advancement without checking remaining bytes",
    },
    {
        "name": "large_stack_buffer",
        "pattern": r'(?:guint8|char|gchar)\s+\w+\s*\[\s*(\d{4,})\s*\]',
        "severity_score": 5.5,
        "cwe": "CWE-121",
        "description": "Large stack buffer — overflow risk if filled from packet data",
    },
]


class PatternScanner:
    def scan_file(self, file_path: str | Path) -> list[dict]:
        """Scan a C source file for dangerous patterns."""
        path = Path(file_path)
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return []

        findings = []
        for pattern_def in VULNERABILITY_PATTERNS:
            for match in re.finditer(pattern_def["pattern"], content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "file": str(path),
                    "line": line_num,
                    "pattern_name": pattern_def["name"],
                    "severity_score": pattern_def["severity_score"],
                    "cwe": pattern_def["cwe"],
                    "description": pattern_def["description"],
                    "detail": match.group(0).strip()[:120],
                })

        findings.sort(key=lambda x: x["severity_score"], reverse=True)
        return findings

    def scan_directory(self, directory: Path, glob_pattern: str = "*.c") -> list[dict]:
        """Scan all matching files in a directory."""
        all_findings = []
        for f in sorted(directory.rglob(glob_pattern)):
            findings = self.scan_file(f)
            all_findings.extend(findings)
        return all_findings
