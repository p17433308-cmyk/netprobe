"""Integer overflow and boundary value mutations."""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass

BOUNDARY_VALUES_8 = [0, 1, 0x7E, 0x7F, 0x80, 0xFE, 0xFF]
BOUNDARY_VALUES_16 = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFE, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
BOUNDARY_VALUES_32 = [
    0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
    0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
]


@dataclass
class OverflowMutator:
    name: str = "overflow"
    rng: random.Random | None = None

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data

        buf = bytearray(data)
        strategy = self.rng.choice(["boundary_8", "boundary_16", "boundary_32", "max_length",
                                     "negative", "zero_length", "overflow_multiply"])

        if strategy == "boundary_8":
            pos = self.rng.randint(0, len(buf) - 1)
            buf[pos] = self.rng.choice(BOUNDARY_VALUES_8)

        elif strategy == "boundary_16" and len(buf) >= 2:
            pos = self.rng.randint(0, len(buf) - 2)
            val = self.rng.choice(BOUNDARY_VALUES_16)
            endian = self.rng.choice(["big", "little"])
            fmt = ">H" if endian == "big" else "<H"
            struct.pack_into(fmt, buf, pos, val)

        elif strategy == "boundary_32" and len(buf) >= 4:
            pos = self.rng.randint(0, len(buf) - 4)
            val = self.rng.choice(BOUNDARY_VALUES_32)
            endian = self.rng.choice(["big", "little"])
            fmt = ">I" if endian == "big" else "<I"
            struct.pack_into(fmt, buf, pos, val)

        elif strategy == "max_length" and len(buf) >= 2:
            pos = self.rng.randint(0, len(buf) - 2)
            width = self.rng.choice([1, 2, 4]) if len(buf) - pos >= 4 else self.rng.choice([1, 2])
            if width == 1:
                buf[pos] = 0xFF
            elif width == 2:
                struct.pack_into(">H", buf, pos, 0xFFFF)
            elif width == 4 and pos + 4 <= len(buf):
                struct.pack_into(">I", buf, pos, 0xFFFFFFFF)

        elif strategy == "negative" and len(buf) >= 4:
            pos = self.rng.randint(0, len(buf) - 4)
            val = self.rng.choice([-1, -2, -128, -32768, -2147483648])
            struct.pack_into(">i", buf, pos, val)

        elif strategy == "zero_length" and len(buf) >= 2:
            pos = self.rng.randint(0, len(buf) - 2)
            width = self.rng.choice([1, 2])
            for i in range(width):
                if pos + i < len(buf):
                    buf[pos + i] = 0

        elif strategy == "overflow_multiply" and len(buf) >= 4:
            pos = self.rng.randint(0, len(buf) - 4)
            large_count = self.rng.choice([0x40000000, 0x20000000, 0x10000001])
            struct.pack_into(">I", buf, pos, large_count)

        return bytes(buf)
