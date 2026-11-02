"""Cross-protocol field transplant mutations."""

from __future__ import annotations

import random


class CrossProtocolMutator:
    """Transplant fields from one protocol into another to confuse parsers."""

    name = "cross_protocol"

    PROTOCOL_FRAGMENTS = {
        "http": [
            b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 99999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        ],
        "tls": [
            b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
            b"\x15\x03\x03\x00\x02\x02\x00",
            b"\x17\x03\x03\xff\xff",
        ],
        "dns": [
            b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
            b"\xc0\x0c" * 20,
            b"\x00\x00\xff\x00\xff",
        ],
        "smb": [
            b"\xfe SMB" + b"\x00" * 60,
            b"\xff SMB" + b"\x00" * 32,
        ],
        "mqtt": [
            b"\x10\x7f" + b"\x00\x04MQTT\x05\xc2\x00\x3c",
            b"\x30\xff\xff\xff\x7f",
        ],
    }

    def mutate(self, data: bytes, count: int = 1, rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._splice_fragment, self._prepend_fragment,
                self._interleave, self._replace_chunk,
            ])
            results.append(strategy(data, rng))
        return results

    def _splice_fragment(self, data: bytes, rng: random.Random) -> bytes:
        proto = rng.choice(list(self.PROTOCOL_FRAGMENTS.keys()))
        fragment = rng.choice(self.PROTOCOL_FRAGMENTS[proto])
        if not data:
            return fragment
        pos = rng.randrange(len(data))
        return data[:pos] + fragment + data[pos:]

    def _prepend_fragment(self, data: bytes, rng: random.Random) -> bytes:
        proto = rng.choice(list(self.PROTOCOL_FRAGMENTS.keys()))
        fragment = rng.choice(self.PROTOCOL_FRAGMENTS[proto])
        return fragment + data

    def _interleave(self, data: bytes, rng: random.Random) -> bytes:
        proto = rng.choice(list(self.PROTOCOL_FRAGMENTS.keys()))
        fragment = rng.choice(self.PROTOCOL_FRAGMENTS[proto])
        chunk_size = rng.randint(4, 32)
        result = bytearray()
        for i in range(0, len(data), chunk_size):
            result += data[i:i + chunk_size]
            if rng.random() < 0.3:
                start = rng.randrange(max(1, len(fragment)))
                end = min(start + rng.randint(1, 8), len(fragment))
                result += fragment[start:end]
        return bytes(result)

    def _replace_chunk(self, data: bytes, rng: random.Random) -> bytes:
        if len(data) < 4:
            return data
        proto = rng.choice(list(self.PROTOCOL_FRAGMENTS.keys()))
        fragment = rng.choice(self.PROTOCOL_FRAGMENTS[proto])
        pos = rng.randrange(len(data) - 1)
        end = min(pos + len(fragment), len(data))
        return data[:pos] + fragment[:end - pos] + data[end:]
