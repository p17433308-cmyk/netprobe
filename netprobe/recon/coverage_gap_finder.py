"""Find parsers with no existing fuzz coverage."""

from __future__ import annotations

import re
from pathlib import Path


class CoverageGapFinder:
    """Identifies dissectors not targeted by OSS-Fuzz or the project's own fuzz harness."""

    def __init__(self, source_path: Path):
        self.source_path = source_path

    def find_fuzz_targets(self) -> set[str]:
        """Parse the OSS-Fuzz harness and build scripts to find covered dissectors."""
        covered = set()

        fuzz_dir = self.source_path / "fuzz"
        if not fuzz_dir.exists():
            fuzz_dir = self.source_path / "tools" / "oss-fuzzshark"

        if fuzz_dir.exists():
            for f in fuzz_dir.rglob("*"):
                if f.suffix in (".c", ".cpp", ".h", ".py", ".sh", ""):
                    try:
                        content = f.read_text(errors="replace")
                    except OSError:
                        continue
                    for m in re.finditer(r'"([a-zA-Z0-9_.]+)"', content):
                        name = m.group(1)
                        if "." in name or "_" in name:
                            covered.add(name.lower())

        cmake = self.source_path / "epan" / "dissectors" / "CMakeLists.txt"
        if cmake.exists():
            pass

        return covered

    def find_gaps(self, parsers: list[dict]) -> list[dict]:
        """Mark parsers that have no fuzz coverage."""
        covered = self.find_fuzz_targets()

        for parser in parsers:
            short = parser.get("short_name", "").lower()
            protocol = parser.get("protocol", "").lower()

            is_covered = (
                short in covered
                or protocol in covered
                or any(short in c for c in covered)
            )
            parser["no_fuzz_coverage"] = not is_covered

        return parsers
