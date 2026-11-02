"""Protocol grammar AST — structured model for packet generation."""

from __future__ import annotations

import struct
import random
from dataclasses import dataclass, field
from typing import Any

from .extractor import ProtocolField, ProtocolGrammar


@dataclass
class PacketTemplate:
    """A template for generating protocol-conformant packets."""
    protocol: str
    fields: list[FieldSpec] = field(default_factory=list)
    min_size: int = 0

    def generate(self, rng: random.Random | None = None) -> bytes:
        rng = rng or random.Random()
        buf = bytearray()
        for fs in self.fields:
            buf.extend(fs.generate(rng))
        return bytes(buf)

    def generate_mutated(self, rng: random.Random | None = None,
                         mutation_rate: float = 0.1) -> bytes:
        rng = rng or random.Random()
        buf = bytearray()
        for fs in self.fields:
            if rng.random() < mutation_rate:
                buf.extend(fs.generate_boundary(rng))
            else:
                buf.extend(fs.generate(rng))
        return bytes(buf)


@dataclass
class FieldSpec:
    """Specification for a single protocol field."""
    name: str
    field_type: str
    size_bytes: int
    encoding: str = "big"
    valid_range: tuple[int, int] | None = None
    boundary_values: list[int] | None = None

    def generate(self, rng: random.Random) -> bytes:
        if self.size_bytes == 0:
            length = rng.randint(0, 32)
            return bytes(rng.choices(range(256), k=length))

        if self.valid_range:
            val = rng.randint(self.valid_range[0], self.valid_range[1])
        else:
            val = rng.randint(0, (1 << (self.size_bytes * 8)) - 1)

        return self._pack(val)

    def generate_boundary(self, rng: random.Random) -> bytes:
        if self.size_bytes == 0:
            choice = rng.choice(["empty", "huge", "null_filled"])
            if choice == "empty":
                return b""
            elif choice == "huge":
                return bytes(rng.choices(range(256), k=rng.randint(256, 4096)))
            else:
                return b"\x00" * rng.randint(1, 64)

        boundaries = self.boundary_values or self._default_boundaries()
        val = rng.choice(boundaries)
        max_val = (1 << (self.size_bytes * 8)) - 1
        val = val & max_val
        return self._pack(val)

    def _pack(self, val: int) -> bytes:
        fmt_map = {1: "B", 2: "H", 4: "I", 8: "Q"}
        fmt_char = fmt_map.get(self.size_bytes)
        if not fmt_char:
            return val.to_bytes(self.size_bytes, byteorder=self.encoding)
        prefix = ">" if self.encoding == "big" else "<"
        return struct.pack(f"{prefix}{fmt_char}", val & ((1 << (self.size_bytes * 8)) - 1))

    def _default_boundaries(self) -> list[int]:
        bits = self.size_bytes * 8
        max_val = (1 << bits) - 1
        half = 1 << (bits - 1)
        return [0, 1, half - 1, half, max_val - 1, max_val]


def grammar_to_template(grammar: ProtocolGrammar) -> PacketTemplate:
    """Convert an extracted grammar into a packet generation template."""
    specs = []
    for pf in grammar.fields:
        enc = "little" if "LE" in pf.encoding else "big"
        fs = FieldSpec(
            name=pf.abbreviation,
            field_type=pf.field_type,
            size_bytes=pf.size_bytes,
            encoding=enc,
        )
        specs.append(fs)

    return PacketTemplate(
        protocol=grammar.short_name,
        fields=specs,
        min_size=sum(s.size_bytes for s in specs if s.size_bytes > 0),
    )
