"""Format string injection mutator."""

from __future__ import annotations

import random


class FormatStringMutator:
    """Inject format specifiers into string fields."""

    name = "format_string"

    PAYLOADS = [
        b"%s" * 50,
        b"%n" * 20,
        b"%x" * 100,
        b"%p" * 50,
        b"%.9999999s",
        b"%99999$n",
        b"%99999$s",
        b"AAAA%08x.%08x.%08x.%08x.%n",
        b"%d" * 200,
        b"\x00%s\x00%s\x00%n",
        b"%1$*1$x" * 20,
        b"%-99999c%3$n",
    ]

    def mutate(self, data: bytes, count: int = 1, rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._inject_at_string, self._replace_all_strings,
                self._append_payload, self._inject_at_null,
            ])
            results.append(strategy(data, rng))
        return results

    def _inject_at_string(self, data: bytes, rng: random.Random) -> bytes:
        printable_runs = []
        start = None
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= 3:
                    printable_runs.append((start, i))
                start = None
        if start is not None and len(data) - start >= 3:
            printable_runs.append((start, len(data)))

        if not printable_runs:
            return data + rng.choice(self.PAYLOADS)

        s, e = rng.choice(printable_runs)
        payload = rng.choice(self.PAYLOADS)
        return data[:s] + payload + data[e:]

    def _replace_all_strings(self, data: bytes, rng: random.Random) -> bytes:
        payload = rng.choice(self.PAYLOADS)
        result = bytearray(data)
        start = None
        replacements = []
        for i, b in enumerate(result):
            if 0x20 <= b <= 0x7E:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= 4:
                    replacements.append((start, i))
                start = None

        offset = 0
        for s, e in replacements:
            s += offset
            e += offset
            result[s:e] = payload
            offset += len(payload) - (e - s)
        return bytes(result)

    def _append_payload(self, data: bytes, rng: random.Random) -> bytes:
        return data + rng.choice(self.PAYLOADS)

    def _inject_at_null(self, data: bytes, rng: random.Random) -> bytes:
        positions = [i for i, b in enumerate(data) if b == 0]
        if not positions:
            return self._append_payload(data, rng)
        pos = rng.choice(positions)
        payload = rng.choice(self.PAYLOADS)
        return data[:pos] + payload + data[pos:]
