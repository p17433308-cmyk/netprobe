"""AI-guided mutations using LLM analysis of parser source."""

from __future__ import annotations

import random
import struct


class AIGuidedMutator:
    """Apply mutations suggested by AI analysis of source code vulnerabilities."""

    name = "ai_guided"

    def mutate_from_suggestions(self, data: bytes, suggestions: list[dict],
                                 rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for suggestion in suggestions:
            mutated = self._apply_suggestion(data, suggestion, rng)
            if mutated != data:
                results.append(mutated)
        return results or [data]

    def mutate(self, data: bytes, count: int = 1, rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._target_length_fields, self._target_count_fields,
                self._target_offset_fields, self._target_type_fields,
                self._maximize_allocations,
            ])
            results.append(strategy(data, rng))
        return results

    def _apply_suggestion(self, data: bytes, suggestion: dict,
                          rng: random.Random) -> bytes:
        offset = suggestion.get("offset", 0)
        size = suggestion.get("size", 1)
        value = suggestion.get("value")

        if offset >= len(data):
            return data

        result = bytearray(data)
        if value is not None:
            if isinstance(value, int):
                if size == 1:
                    result[offset:offset + 1] = struct.pack("!B", value & 0xFF)
                elif size == 2:
                    result[offset:offset + 2] = struct.pack("!H", value & 0xFFFF)
                elif size == 4:
                    result[offset:offset + 4] = struct.pack("!I", value & 0xFFFFFFFF)
            elif isinstance(value, bytes):
                result[offset:offset + len(value)] = value
        return bytes(result)

    def _target_length_fields(self, data: bytes, rng: random.Random) -> bytes:
        if len(data) < 4:
            return data
        result = bytearray(data)
        dangerous_values = [0, 0xFFFF, 0xFFFE, 0x7FFF, len(data) + 1000, len(data) * 2]
        for i in range(0, min(len(data) - 1, 20), 2):
            val = struct.unpack("!H", data[i:i + 2])[0]
            if 1 < val < len(data):
                new_val = rng.choice(dangerous_values)
                result[i:i + 2] = struct.pack("!H", new_val & 0xFFFF)
                break
        return bytes(result)

    def _target_count_fields(self, data: bytes, rng: random.Random) -> bytes:
        if len(data) < 2:
            return data
        result = bytearray(data)
        for i in range(min(len(data), 16)):
            if 0 < data[i] < 20:
                result[i] = rng.choice([0, 255, data[i] * 10, 0x7F])
                break
        return bytes(result)

    def _target_offset_fields(self, data: bytes, rng: random.Random) -> bytes:
        if len(data) < 6:
            return data
        result = bytearray(data)
        for i in range(0, min(len(data) - 3, 24), 2):
            val = struct.unpack("!H", data[i:i + 2])[0]
            if val < len(data) and val > 4:
                new_val = rng.choice([0, len(data) - 1, len(data), len(data) + 100, 0xFFFF])
                result[i:i + 2] = struct.pack("!H", new_val & 0xFFFF)
                break
        return bytes(result)

    def _target_type_fields(self, data: bytes, rng: random.Random) -> bytes:
        if not data:
            return data
        result = bytearray(data)
        result[0] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randint(0, 255)])
        return bytes(result)

    def _maximize_allocations(self, data: bytes, rng: random.Random) -> bytes:
        result = bytearray(data)
        for i in range(0, min(len(data) - 1, 20), 2):
            result[i:i + 2] = b"\xff\xff"
        return bytes(result)
