"""Map all parsers/dissectors in a target tool's source tree."""

from __future__ import annotations

import re
from pathlib import Path

from netprobe.core.target_registry import get_target

PROTOCOL_PATTERN = re.compile(
    r'proto_register_protocol\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"',
)
DISSECTOR_TABLE_PATTERN = re.compile(
    r'dissector_add_uint\s*\(\s*"([^"]+)"\s*,\s*(\d+)',
)
HEURISTIC_PATTERN = re.compile(
    r'heur_dissector_add\s*\(\s*"([^"]+)"',
)


class SourceMapper:
    def __init__(self, source_path: Path, target_name: str = "wireshark"):
        self.source_path = source_path
        self.target = get_target(target_name)

    def map_all(self) -> list[dict]:
        parsers = []
        glob_pattern = self.target.parser_glob
        for src_file in sorted(self.source_path.glob(glob_pattern)):
            info = self._analyze_file(src_file)
            if info:
                parsers.append(info)
        return parsers

    def _analyze_file(self, path: Path) -> dict | None:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return None

        lines = content.split("\n")
        line_count = len(lines)

        protocol_name = "unknown"
        short_name = path.stem.replace("packet-", "").replace("file-", "")
        long_name = short_name

        for m in PROTOCOL_PATTERN.finditer(content):
            long_name = m.group(1)
            protocol_name = m.group(2)
            short_name = m.group(3)
            break

        has_port = bool(DISSECTOR_TABLE_PATTERN.search(content))
        has_heuristic = bool(HEURISTIC_PATTERN.search(content))

        tvb_calls = len(re.findall(r'\btvb_(?:memcpy|get_string|get_bytes)\b', content))
        tvb_get_calls = len(re.findall(r'\btvb_get_(?:guint|gint|letoh)\w+\b', content))
        malloc_calls = len(re.findall(r'\bwmem_alloc\b|\bg_malloc\b|\bmalloc\b', content))
        memcpy_calls = len(re.findall(r'\bmemcpy\b|\btvb_memcpy\b', content))
        loop_count = len(re.findall(r'\bfor\s*\(|while\s*\(', content))
        recursion = bool(re.search(
            r'call_dissector\s*\(|dissector_try_uint\s*\(', content
        ))

        return {
            "path": str(path),
            "filename": path.name,
            "protocol": protocol_name,
            "short_name": short_name,
            "long_name": long_name,
            "lines": line_count,
            "has_port_registration": has_port,
            "has_heuristic": has_heuristic,
            "tvb_data_calls": tvb_calls,
            "tvb_get_calls": tvb_get_calls,
            "malloc_calls": malloc_calls,
            "memcpy_calls": memcpy_calls,
            "loop_count": loop_count,
            "has_recursion": recursion,
            "dangerous_calls": tvb_calls + memcpy_calls + malloc_calls,
        }
