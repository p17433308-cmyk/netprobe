"""Mutation engine — orchestrates mutation strategies."""

from __future__ import annotations

import random
from pathlib import Path

from .bitflip import BitFlipMutator
from .overflow import OverflowMutator
from .magic import MagicValueMutator
from .structure_aware import StructureAwareMutator


MUTATOR_REGISTRY: dict[str, type] = {
    "bitflip": BitFlipMutator,
    "overflow": OverflowMutator,
    "magic": MagicValueMutator,
    "structure": StructureAwareMutator,
}


class MutationEngine:
    def __init__(self, mutator_names: list[str] | None = None, seed: int | None = None):
        self.rng = random.Random(seed)
        names = mutator_names or ["bitflip", "overflow", "magic"]
        self.mutators = []
        for name in names:
            cls = MUTATOR_REGISTRY.get(name)
            if cls:
                self.mutators.append(cls(rng=self.rng))

        self.energy: dict[str, float] = {m.name: 1.0 for m in self.mutators}

    def mutate(self, data: bytes, count: int = 1) -> list[bytes]:
        """Generate `count` mutations of the input data."""
        results = []
        for _ in range(count):
            mutator = self._select_mutator()
            mutated = mutator.mutate(data)
            results.append(mutated)
        return results

    def _select_mutator(self):
        """Energy-based mutator selection — favor mutators that found coverage/crashes."""
        total = sum(self.energy.values())
        r = self.rng.random() * total
        cumulative = 0.0
        for m in self.mutators:
            cumulative += self.energy[m.name]
            if r <= cumulative:
                return m
        return self.mutators[-1]

    def boost(self, mutator_name: str, factor: float = 1.5):
        """Boost a mutator's energy (e.g., after finding a crash)."""
        if mutator_name in self.energy:
            self.energy[mutator_name] *= factor

    def mutate_pcap(self, pcap_path: Path, count: int = 1) -> list[bytes]:
        """Read a pcap file and generate mutations of its raw bytes."""
        data = pcap_path.read_bytes()
        return self.mutate(data, count)
