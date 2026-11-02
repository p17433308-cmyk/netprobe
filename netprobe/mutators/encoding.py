"""Charset and encoding attack mutations."""

from __future__ import annotations

import random


class EncodingMutator:
    """Generate encoding attacks: UTF-8 overlong, BOM injection, mixed encodings."""

    name = "encoding"

    OVERLONG_ENCODINGS = {
        0x2F: [b"\xC0\xAF", b"\xE0\x80\xAF", b"\xF0\x80\x80\xAF"],
        0x00: [b"\xC0\x80", b"\xE0\x80\x80", b"\xF0\x80\x80\x80"],
        0x2E: [b"\xC0\xAE", b"\xE0\x80\xAE"],
        0x5C: [b"\xC1\x9C", b"\xE0\x81\x9C"],
    }

    BOM_MARKERS = [
        b"\xEF\xBB\xBF",      # UTF-8
        b"\xFF\xFE",            # UTF-16 LE
        b"\xFE\xFF",            # UTF-16 BE
        b"\xFF\xFE\x00\x00",   # UTF-32 LE
        b"\x00\x00\xFE\xFF",   # UTF-32 BE
    ]

    INVALID_UTF8 = [
        b"\x80", b"\xBF", b"\xFE", b"\xFF",
        b"\xC0\x80", b"\xC1\xBF",
        b"\xED\xA0\x80",  # surrogate half
        b"\xF4\x90\x80\x80",  # beyond U+10FFFF
        b"\xF8\x80\x80\x80\x80",  # 5-byte (invalid)
        b"\xFC\x80\x80\x80\x80\x80",  # 6-byte (invalid)
    ]

    def mutate(self, data: bytes, count: int = 1, rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._overlong_replace, self._bom_inject,
                self._invalid_utf8_inject, self._mixed_encoding,
                self._null_byte_inject,
            ])
            results.append(strategy(data, rng))
        return results

    def _overlong_replace(self, data: bytes, rng: random.Random) -> bytes:
        result = bytearray()
        for b in data:
            if b in self.OVERLONG_ENCODINGS and rng.random() < 0.3:
                result += rng.choice(self.OVERLONG_ENCODINGS[b])
            else:
                result.append(b)
        return bytes(result)

    def _bom_inject(self, data: bytes, rng: random.Random) -> bytes:
        bom = rng.choice(self.BOM_MARKERS)
        pos = rng.randrange(max(1, len(data))) if data else 0
        return data[:pos] + bom + data[pos:]

    def _invalid_utf8_inject(self, data: bytes, rng: random.Random) -> bytes:
        result = bytearray(data)
        num_injections = rng.randint(1, 10)
        for _ in range(num_injections):
            payload = rng.choice(self.INVALID_UTF8)
            pos = rng.randrange(max(1, len(result)))
            result[pos:pos] = payload
        return bytes(result)

    def _mixed_encoding(self, data: bytes, rng: random.Random) -> bytes:
        chunks = []
        for i in range(0, len(data), rng.randint(4, 16)):
            chunk = data[i:i + rng.randint(4, 16)]
            encoding = rng.choice(["raw", "utf16le", "utf16be", "latin1"])
            if encoding == "utf16le":
                try:
                    chunks.append(chunk.decode("latin-1").encode("utf-16-le"))
                except Exception:
                    chunks.append(chunk)
            elif encoding == "utf16be":
                try:
                    chunks.append(chunk.decode("latin-1").encode("utf-16-be"))
                except Exception:
                    chunks.append(chunk)
            else:
                chunks.append(chunk)
        return b"".join(chunks)

    def _null_byte_inject(self, data: bytes, rng: random.Random) -> bytes:
        result = bytearray(data)
        num = rng.randint(1, 10)
        for _ in range(num):
            pos = rng.randrange(max(1, len(result)))
            result.insert(pos, 0)
        return bytes(result)
