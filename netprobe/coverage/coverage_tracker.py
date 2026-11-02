"""Track coverage bitmaps and detect new edges."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class CoverageSnapshot:
    edges_hit: set[str] = field(default_factory=set)
    total_edges: int = 0
    new_edges: int = 0


class CoverageTracker:
    """Track which code edges have been reached across all executions."""

    def __init__(self):
        self.global_edges: set[str] = set()
        self.edge_counts: dict[str, int] = {}

    def update(self, stderr: str) -> CoverageSnapshot:
        edges = self._extract_edges(stderr)
        new = edges - self.global_edges
        self.global_edges |= edges

        for e in edges:
            self.edge_counts[e] = self.edge_counts.get(e, 0) + 1

        return CoverageSnapshot(
            edges_hit=edges,
            total_edges=len(self.global_edges),
            new_edges=len(new),
        )

    def has_new_coverage(self, stderr: str) -> bool:
        edges = self._extract_edges(stderr)
        return bool(edges - self.global_edges)

    def _extract_edges(self, stderr: str) -> set[str]:
        edges = set()
        for line in stderr.split("\n"):
            if "at " in line and (":" in line):
                edge_id = hashlib.md5(line.strip().encode()).hexdigest()[:12]
                edges.add(edge_id)
            if "#" in line and "0x" in line:
                edge_id = hashlib.md5(line.strip().encode()).hexdigest()[:12]
                edges.add(edge_id)
        return edges

    @property
    def total_edges(self) -> int:
        return len(self.global_edges)

    def rare_edges(self, threshold: int = 3) -> set[str]:
        return {e for e, c in self.edge_counts.items() if c <= threshold}
