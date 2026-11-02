"""Extract protocol grammars from Wireshark dissector source code.

Parses hf_ (header field) array definitions to build a structured model
of protocol fields, their types, sizes, and encodings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ProtocolField:
    name: str
    abbreviation: str
    field_type: str
    display: str
    size_bytes: int = 0
    encoding: str = "ENC_BIG_ENDIAN"
    bitmask: int = 0
    description: str = ""
    value_strings: list[tuple[int, str]] | None = None


@dataclass
class ProtocolGrammar:
    protocol_name: str
    short_name: str
    fields: list[ProtocolField] = field(default_factory=list)
    subtrees: list[str] = field(default_factory=list)
    source_file: str = ""

    def field_count(self) -> int:
        return len(self.fields)

    def total_min_size(self) -> int:
        return sum(f.size_bytes for f in self.fields if f.size_bytes > 0)


FTYPE_SIZES = {
    "FT_UINT8": 1, "FT_INT8": 1, "FT_BOOLEAN": 1,
    "FT_UINT16": 2, "FT_INT16": 2,
    "FT_UINT24": 3, "FT_INT24": 3,
    "FT_UINT32": 4, "FT_INT32": 4, "FT_IPv4": 4, "FT_FLOAT": 4,
    "FT_UINT48": 6,
    "FT_UINT64": 8, "FT_INT64": 8, "FT_DOUBLE": 8,
    "FT_ETHER": 6, "FT_IPv6": 16, "FT_EUI64": 8, "FT_GUID": 16,
    "FT_BYTES": 0, "FT_STRING": 0, "FT_STRINGZ": 0, "FT_UINT_STRING": 0,
    "FT_NONE": 0, "FT_PROTOCOL": 0, "FT_FRAMENUM": 4,
    "FT_ABSOLUTE_TIME": 8, "FT_RELATIVE_TIME": 8,
}

HF_ENTRY_RE = re.compile(
    r'\{\s*&\s*(hf_\w+)\s*,'
    r'\s*\{\s*"([^"]*?)"\s*,'       # name
    r'\s*"([^"]*?)"\s*,'            # abbreviation
    r'\s*(FT_\w+)\s*,'              # type
    r'\s*(\w+)\s*,'                 # display
    r'\s*(\w+)\s*,'                 # strings/NULL
    r'\s*(0x[0-9a-fA-F]+|\d+)\s*,' # bitmask
    r'\s*("(?:[^"\\]|\\.)*"|NULL)\s*,' # blurb
    r'\s*HFILL',
    re.DOTALL,
)

PROTO_REG_RE = re.compile(
    r'proto_register_protocol\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"'
)

ETT_RE = re.compile(r'static\s+gint\s+(ett_\w+)')


class GrammarExtractor:
    """Extract protocol grammars from Wireshark dissector C source files."""

    def extract_from_file(self, path: Path) -> ProtocolGrammar | None:
        try:
            content = path.read_text(errors="replace")
        except OSError:
            return None

        proto_match = PROTO_REG_RE.search(content)
        if not proto_match:
            return None

        grammar = ProtocolGrammar(
            protocol_name=proto_match.group(1),
            short_name=proto_match.group(3),
            source_file=str(path),
        )

        for m in HF_ENTRY_RE.finditer(content):
            ftype = m.group(4)
            bitmask_str = m.group(7)
            bitmask = int(bitmask_str, 0) if bitmask_str != "0" else 0

            blurb = m.group(8)
            desc = blurb.strip('"') if blurb != "NULL" else ""

            pf = ProtocolField(
                name=m.group(2),
                abbreviation=m.group(3),
                field_type=ftype,
                display=m.group(5),
                size_bytes=FTYPE_SIZES.get(ftype, 0),
                bitmask=bitmask,
                description=desc,
            )
            grammar.fields.append(pf)

        for m in ETT_RE.finditer(content):
            grammar.subtrees.append(m.group(1))

        return grammar if grammar.fields else None

    def extract_from_directory(self, source_dir: Path,
                                glob: str = "epan/dissectors/packet-*.c") -> list[ProtocolGrammar]:
        grammars = []
        for path in sorted(source_dir.glob(glob)):
            g = self.extract_from_file(path)
            if g:
                grammars.append(g)
        return grammars
