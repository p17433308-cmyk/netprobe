"""Magic value mutations — known-bad values that trigger parser bugs."""

from __future__ import annotations

import random
from dataclasses import dataclass

MAGIC_STRINGS = [
    b"\x00" * 256,
    b"\xFF" * 256,
    b"\x41" * 1024,
    b"%s" * 32,
    b"%n" * 16,
    b"%x" * 32,
    b"AAAA" * 256,
    b"\x00\x00\x00\x00",
    b"\xFF\xFF\xFF\xFF",
    b"\x80\x00\x00\x00",
    b"\x7F\xFF\xFF\xFF",
    b"\x00\x01",
    b"\xFF\xFE",
    b"\xFE\xFF",
    b"\xEF\xBB\xBF",
    b"\x00" * 1,
    b"\x00" * 4096,
]

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

FORMAT_STRINGS = [
    b"%s%s%s%s%s%s%s%s%s%s",
    b"%n%n%n%n%n%n",
    b"%x" * 50,
    b"%.9999999s",
    b"%99999c",
    b"AAAA%08x.%08x.%08x.%08x.%n",
]


@dataclass
class MagicValueMutator:
    name: str = "magic"
    rng: random.Random | None = None

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 8:
            return data

        buf = bytearray(data)
        strategy = self.rng.choice([
            "insert_magic", "replace_with_magic", "corrupt_header",
            "extend_data", "null_terminate_early", "format_string",
        ])

        if strategy == "insert_magic":
            pos = self.rng.randint(0, len(buf))
            magic = self.rng.choice(MAGIC_STRINGS)
            chunk = magic[:self.rng.randint(1, min(64, len(magic)))]
            buf[pos:pos] = chunk

        elif strategy == "replace_with_magic":
            pos = self.rng.randint(0, max(0, len(buf) - 4))
            magic = self.rng.choice(MAGIC_STRINGS)
            length = min(len(magic), len(buf) - pos, 64)
            buf[pos:pos + length] = magic[:length]

        elif strategy == "corrupt_header":
            if buf[:4] == bytearray(PCAP_MAGIC):
                field = self.rng.choice(["version", "snaplen", "linktype"])
                if field == "version":
                    buf[4:6] = b"\xFF\xFF"
                elif field == "snaplen":
                    buf[16:20] = b"\xFF\xFF\xFF\xFF"
                elif field == "linktype":
                    buf[20:24] = b"\xFF\xFF\xFF\xFF"
            elif buf[:4] == bytearray(PCAPNG_MAGIC):
                buf[8:10] = b"\xFF\xFF"

        elif strategy == "extend_data":
            extension = bytes(self.rng.choices(range(256), k=self.rng.randint(100, 4096)))
            buf.extend(extension)

        elif strategy == "null_terminate_early":
            pos = self.rng.randint(8, max(8, len(buf) - 1))
            buf[pos] = 0

        elif strategy == "format_string":
            pos = self.rng.randint(0, max(0, len(buf) - 10))
            fmt = self.rng.choice(FORMAT_STRINGS)
            length = min(len(fmt), len(buf) - pos)
            buf[pos:pos + length] = fmt[:length]

        return bytes(buf)
