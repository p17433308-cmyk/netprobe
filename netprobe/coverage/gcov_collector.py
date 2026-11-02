"""Collect code coverage data from gcov/llvm-cov instrumented binaries."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CoverageData:
    total_lines: int = 0
    covered_lines: int = 0
    total_branches: int = 0
    covered_branches: int = 0
    file_coverage: dict[str, float] = field(default_factory=dict)
    new_edges: int = 0

    @property
    def line_rate(self) -> float:
        return self.covered_lines / max(self.total_lines, 1)

    @property
    def branch_rate(self) -> float:
        return self.covered_branches / max(self.total_branches, 1)


class GcovCollector:
    """Collect and parse gcov/llvm-cov coverage data."""

    def __init__(self, build_dir: Path | None = None):
        self.build_dir = build_dir
        self.baseline_edges: set[str] = set()

    def collect(self, source_dir: Path | None = None) -> CoverageData:
        """Run gcov and parse results."""
        if self.build_dir:
            return self._collect_gcov()
        return CoverageData()

    def _collect_gcov(self) -> CoverageData:
        data = CoverageData()
        try:
            result = subprocess.run(
                ["find", str(self.build_dir), "-name", "*.gcda"],
                capture_output=True, text=True, timeout=30,
            )
            gcda_files = result.stdout.strip().split("\n")
            gcda_files = [f for f in gcda_files if f]

            for gcda in gcda_files[:100]:
                gcda_path = Path(gcda)
                try:
                    proc = subprocess.run(
                        ["gcov", "-b", str(gcda_path)],
                        capture_output=True, text=True, timeout=10,
                        cwd=gcda_path.parent,
                    )
                    self._parse_gcov_output(proc.stdout, data)
                except (subprocess.TimeoutExpired, OSError):
                    continue

        except (subprocess.TimeoutExpired, OSError):
            pass

        return data

    def _parse_gcov_output(self, output: str, data: CoverageData):
        for line in output.split("\n"):
            m = re.match(r"Lines executed:(\d+\.\d+)% of (\d+)", line)
            if m:
                pct = float(m.group(1))
                total = int(m.group(2))
                data.total_lines += total
                data.covered_lines += int(total * pct / 100)

            m = re.match(r"Branches executed:(\d+\.\d+)% of (\d+)", line)
            if m:
                pct = float(m.group(1))
                total = int(m.group(2))
                data.total_branches += total
                data.covered_branches += int(total * pct / 100)

    def compute_new_edges(self, current_edges: set[str]) -> int:
        """Compare current coverage to baseline, return count of new edges."""
        new = current_edges - self.baseline_edges
        self.baseline_edges |= current_edges
        return len(new)

    def reset_counters(self):
        """Reset gcov counters for a fresh measurement."""
        if self.build_dir:
            subprocess.run(
                ["find", str(self.build_dir), "-name", "*.gcda", "-delete"],
                capture_output=True, timeout=30,
            )
