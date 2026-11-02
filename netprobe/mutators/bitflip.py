"""Bit and byte flip mutations."""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class BitFlipMutator:
    name: str = "bitflip"
    rng: random.Random | None = None

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 1:
            return data

        buf = bytearray(data)
        strategy = self.rng.choice(["single_bit", "byte_flip", "multi_bit", "walking_byte"])

        if strategy == "single_bit":
            pos = self.rng.randint(0, len(buf) - 1)
            bit = self.rng.randint(0, 7)
            buf[pos] ^= 1 << bit

        elif strategy == "byte_flip":
            pos = self.rng.randint(0, len(buf) - 1)
            buf[pos] ^= 0xFF

        elif strategy == "multi_bit":
            num_flips = self.rng.randint(2, min(8, len(buf)))
            for _ in range(num_flips):
                pos = self.rng.randint(0, len(buf) - 1)
                bit = self.rng.randint(0, 7)
                buf[pos] ^= 1 << bit

        elif strategy == "walking_byte":
            start = self.rng.randint(0, max(0, len(buf) - 4))
            length = self.rng.randint(1, min(4, len(buf) - start))
            for i in range(start, start + length):
                buf[i] ^= 0xFF

        return bytes(buf)
