"""Structure-aware mutations that target protocol framing."""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass


@dataclass
class StructureAwareMutator:
    name: str = "structure"
    rng: random.Random | None = None

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 24:
            return data

        buf = bytearray(data)

        is_pcap = buf[:4] in (bytearray(b"\xd4\xc3\xb2\xa1"), bytearray(b"\xa1\xb2\xc3\xd4"))

        if is_pcap and len(buf) > 40:
            strategy = self.rng.choice([
                "mutate_packet_length", "duplicate_packet", "truncate_packet",
                "inject_packet", "corrupt_payload_length", "nest_deep",
            ])
        else:
            strategy = self.rng.choice([
                "mutate_length_fields", "corrupt_payload_length",
                "duplicate_tlv", "nest_deep",
            ])

        if strategy == "mutate_packet_length":
            pkt_offset = 24
            if pkt_offset + 16 <= len(buf):
                orig_len = struct.unpack_from("<I", buf, pkt_offset + 8)[0]
                new_len = self.rng.choice([
                    0, 1, orig_len - 1, orig_len + 1,
                    orig_len * 2, 0xFFFF, 0xFFFFFFFF, orig_len + 65536,
                ])
                struct.pack_into("<I", buf, pkt_offset + 8, new_len & 0xFFFFFFFF)
                struct.pack_into("<I", buf, pkt_offset + 12, new_len & 0xFFFFFFFF)

        elif strategy == "duplicate_packet" and len(buf) > 40:
            pkt_start = 24
            pkt_hdr_size = 16
            if pkt_start + pkt_hdr_size <= len(buf):
                caplen = struct.unpack_from("<I", buf, pkt_start + 8)[0]
                pkt_end = min(pkt_start + pkt_hdr_size + caplen, len(buf))
                packet = buf[pkt_start:pkt_end]
                copies = self.rng.randint(2, 100)
                for _ in range(copies):
                    buf.extend(packet)

        elif strategy == "truncate_packet" and len(buf) > 40:
            pkt_start = 24
            if pkt_start + 16 <= len(buf):
                caplen = struct.unpack_from("<I", buf, pkt_start + 8)[0]
                new_len = max(1, caplen // self.rng.randint(2, 10))
                struct.pack_into("<I", buf, pkt_start + 8, new_len)

        elif strategy == "inject_packet":
            fake_pkt_hdr = struct.pack("<IIII", 0, 0, 64, 64)
            fake_payload = bytes(self.rng.choices(range(256), k=64))
            buf.extend(fake_pkt_hdr + fake_payload)

        elif strategy == "corrupt_payload_length":
            for offset in range(24, min(len(buf) - 2, 200), 2):
                val = struct.unpack_from(">H", buf, offset)[0]
                if 4 <= val <= 1500:
                    new_val = self.rng.choice([0, 1, val - 1, 0xFFFF, val * 10])
                    struct.pack_into(">H", buf, offset, new_val & 0xFFFF)
                    break

        elif strategy == "nest_deep":
            depth = self.rng.randint(50, 500)
            nested = bytearray()
            for _ in range(depth):
                layer_len = self.rng.randint(4, 20)
                nested.extend(struct.pack(">H", layer_len))
                nested.extend(bytes(self.rng.choices(range(256), k=layer_len)))
            if len(buf) > 40:
                insert_pos = self.rng.randint(40, len(buf))
                buf[insert_pos:insert_pos] = nested

        return bytes(buf)
