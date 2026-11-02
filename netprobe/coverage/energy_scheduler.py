"""Energy-based scheduling — allocate more mutations to inputs that find new coverage."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class InputEnergy:
    content_hash: str
    base_energy: float = 1.0
    new_edges_found: int = 0
    crashes_found: int = 0
    times_selected: int = 0
    stale_rounds: int = 0

    @property
    def energy(self) -> float:
        e = self.base_energy
        e *= (1 + self.new_edges_found * 0.5)
        e *= (1 + self.crashes_found * 2.0)
        decay = max(0.1, 1.0 / (1 + self.stale_rounds * 0.05))
        e *= decay
        return e


class EnergyScheduler:
    """Schedule fuzzing energy based on coverage feedback."""

    def __init__(self):
        self.inputs: dict[str, InputEnergy] = {}

    def register(self, content_hash: str, found_new: bool = False, found_crash: bool = False):
        if content_hash not in self.inputs:
            self.inputs[content_hash] = InputEnergy(content_hash=content_hash)

        entry = self.inputs[content_hash]
        if found_new:
            entry.new_edges_found += 1
            entry.stale_rounds = 0
        if found_crash:
            entry.crashes_found += 1
            entry.stale_rounds = 0

    def select(self, rng) -> str | None:
        if not self.inputs:
            return None

        entries = list(self.inputs.values())
        total = sum(e.energy for e in entries)
        if total <= 0:
            return rng.choice(entries).content_hash

        r = rng.random() * total
        cumulative = 0.0
        for e in entries:
            cumulative += e.energy
            if r <= cumulative:
                e.times_selected += 1
                return e.content_hash
        return entries[-1].content_hash

    def decay_all(self):
        for e in self.inputs.values():
            e.stale_rounds += 1

    def mutation_count(self, content_hash: str, base: int = 10) -> int:
        if content_hash not in self.inputs:
            return base
        energy = self.inputs[content_hash].energy
        return max(1, int(base * math.log2(1 + energy)))
