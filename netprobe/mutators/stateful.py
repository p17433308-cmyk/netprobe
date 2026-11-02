"""Multi-packet sequence mutations."""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class StatefulMutator:
    """Mutate multi-packet sequences: reorder, replay, inject, drop."""

    name = "stateful"

    def mutate(self, packets: list[bytes], count: int = 1, rng: random.Random | None = None) -> list[list[bytes]]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._reorder, self._replay, self._inject_mid,
                self._drop_packet, self._duplicate_all, self._reverse,
                self._truncate_sequence,
            ])
            mutated = strategy(list(packets), rng)
            results.append(mutated)
        return results

    def _reorder(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        if len(packets) < 2:
            return packets
        i, j = rng.sample(range(len(packets)), 2)
        packets[i], packets[j] = packets[j], packets[i]
        return packets

    def _replay(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        if not packets:
            return packets
        idx = rng.randrange(len(packets))
        insert_at = rng.randrange(len(packets) + 1)
        packets.insert(insert_at, packets[idx])
        return packets

    def _inject_mid(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        garbage = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        idx = rng.randrange(max(1, len(packets)))
        packets.insert(idx, garbage)
        return packets

    def _drop_packet(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        if len(packets) < 2:
            return packets
        idx = rng.randrange(len(packets))
        packets.pop(idx)
        return packets

    def _duplicate_all(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        return packets + packets

    def _reverse(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        return packets[::-1]

    def _truncate_sequence(self, packets: list[bytes], rng: random.Random) -> list[bytes]:
        if len(packets) < 2:
            return packets
        cut = rng.randint(1, len(packets) - 1)
        return packets[:cut]
