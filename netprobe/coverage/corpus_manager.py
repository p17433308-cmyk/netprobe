"""Manage and evolve the fuzzing corpus based on coverage."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class CorpusEntry:
    path: Path
    size: int
    content_hash: str
    found_new_coverage: bool = False
    crash_count: int = 0
    mutation_source: str = ""
    energy: float = 1.0


class CorpusManager:
    """Maintain, minimize, and evolve the seed corpus."""

    def __init__(self, corpus_dir: Path, max_size: int = 10000):
        self.corpus_dir = corpus_dir
        self.max_size = max_size
        self.entries: dict[str, CorpusEntry] = {}
        self.seen_hashes: set[str] = set()
        corpus_dir.mkdir(parents=True, exist_ok=True)
        self._load_existing()

    def _load_existing(self):
        for f in self.corpus_dir.glob("*.pcap"):
            data = f.read_bytes()
            h = hashlib.sha256(data).hexdigest()[:16]
            if h not in self.seen_hashes:
                self.seen_hashes.add(h)
                self.entries[h] = CorpusEntry(
                    path=f, size=len(data), content_hash=h,
                )

    def add(self, data: bytes, found_coverage: bool = False,
            source: str = "") -> CorpusEntry | None:
        """Add a new input to the corpus if it's unique."""
        h = hashlib.sha256(data).hexdigest()[:16]
        if h in self.seen_hashes:
            return None

        self.seen_hashes.add(h)
        path = self.corpus_dir / f"corpus_{h}.pcap"
        path.write_bytes(data)

        entry = CorpusEntry(
            path=path, size=len(data), content_hash=h,
            found_new_coverage=found_coverage,
            mutation_source=source,
            energy=2.0 if found_coverage else 1.0,
        )
        self.entries[h] = entry

        if len(self.entries) > self.max_size:
            self._evict()

        return entry

    def select(self, rng) -> CorpusEntry | None:
        """Select a corpus entry weighted by energy."""
        if not self.entries:
            return None

        entries = list(self.entries.values())
        total = sum(e.energy for e in entries)
        r = rng.random() * total
        cumulative = 0.0
        for e in entries:
            cumulative += e.energy
            if r <= cumulative:
                return e
        return entries[-1]

    def boost(self, content_hash: str, factor: float = 1.5):
        if content_hash in self.entries:
            self.entries[content_hash].energy *= factor

    def _evict(self):
        """Remove lowest-energy entries to stay under max_size."""
        sorted_entries = sorted(self.entries.values(), key=lambda e: e.energy)
        while len(self.entries) > self.max_size:
            entry = sorted_entries.pop(0)
            entry.path.unlink(missing_ok=True)
            del self.entries[entry.content_hash]

    @property
    def size(self) -> int:
        return len(self.entries)
