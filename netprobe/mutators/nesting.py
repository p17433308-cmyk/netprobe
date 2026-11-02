"""Deep nesting mutations — recursive encapsulation attacks."""

from __future__ import annotations

import random
import struct


class NestingMutator:
    """Generate deeply nested protocol structures to trigger stack exhaustion."""

    name = "nesting"

    ENCAPSULATION_HEADERS = {
        "vlan": b"\x81\x00",
        "mpls": struct.pack("!I", 0x00001100),
        "gre": struct.pack("!HH", 0x0000, 0x0800),
        "ip_in_ip": b"\x45\x00\x00\x28" + b"\x00" * 16,
        "vxlan": b"\x08\x00\x00\x00" + b"\x00\x00\x00\x00",
    }

    def mutate(self, data: bytes, count: int = 1, rng: random.Random | None = None) -> list[bytes]:
        rng = rng or random.Random()
        results = []
        for _ in range(count):
            strategy = rng.choice([
                self._deep_vlan, self._nested_tunnels,
                self._recursive_tlv, self._deep_asn1,
                self._nested_dns_compression,
            ])
            results.append(strategy(data, rng))
        return results

    def _deep_vlan(self, data: bytes, rng: random.Random) -> bytes:
        depth = rng.randint(50, 500)
        header = b""
        for i in range(depth):
            vlan_id = rng.randint(1, 4094)
            tci = (0 << 13) | vlan_id
            header += struct.pack("!HH", 0x8100, tci)
        header += struct.pack("!H", 0x0800)
        return header + data

    def _nested_tunnels(self, data: bytes, rng: random.Random) -> bytes:
        depth = rng.randint(10, 100)
        result = data
        for _ in range(depth):
            wrapper = rng.choice(list(self.ENCAPSULATION_HEADERS.values()))
            result = wrapper + result
        return result

    def _recursive_tlv(self, data: bytes, rng: random.Random) -> bytes:
        depth = rng.randint(100, 1000)
        result = data
        for _ in range(depth):
            tag = rng.randint(0, 255)
            length = len(result) & 0xFFFF
            result = struct.pack("!BH", tag, length) + result
        return result

    def _deep_asn1(self, data: bytes, rng: random.Random) -> bytes:
        depth = rng.randint(100, 500)
        result = data
        for _ in range(depth):
            tag = 0x30
            length = len(result)
            if length < 128:
                header = bytes([tag, length])
            elif length < 256:
                header = bytes([tag, 0x81, length])
            else:
                header = bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF])
            result = header + result
        return result

    def _nested_dns_compression(self, data: bytes, rng: random.Random) -> bytes:
        count = rng.randint(50, 200)
        result = bytearray()
        for i in range(count):
            offset = (i * 2) % 0x3FFF
            result += struct.pack("!H", 0xC000 | offset)
        result += data
        return bytes(result)
