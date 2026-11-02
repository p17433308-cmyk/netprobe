"""Parse RFC specs to augment protocol grammars."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class RFCField:
    name: str
    bits: int
    offset_bits: int
    description: str = ""
    valid_values: list[int] = field(default_factory=list)
    constraints: str = ""


@dataclass
class RFCGrammar:
    protocol: str
    rfc_number: str
    fields: list[RFCField] = field(default_factory=list)


class RFCParser:
    """Extract field definitions from RFC ASCII art diagrams."""

    DIAGRAM_PATTERN = re.compile(
        r"^\s*\+-+(?:\+-+)*\+\s*$", re.MULTILINE
    )
    FIELD_ROW_PATTERN = re.compile(
        r"\|\s*([^|]+?)\s*\|"
    )
    BIT_RULER_PATTERN = re.compile(
        r"^\s*0\s+.*(?:1[56]|31)\s*$", re.MULTILINE
    )

    def parse_text(self, text: str, protocol: str = "unknown",
                   rfc: str = "unknown") -> RFCGrammar:
        grammar = RFCGrammar(protocol=protocol, rfc_number=rfc)

        diagrams = self._find_diagrams(text)
        for diagram in diagrams:
            fields = self._parse_diagram(diagram)
            grammar.fields.extend(fields)

        return grammar

    def parse_file(self, path: str, protocol: str = "unknown",
                   rfc: str = "unknown") -> RFCGrammar:
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except Exception:
            return RFCGrammar(protocol=protocol, rfc_number=rfc)
        return self.parse_text(text, protocol, rfc)

    def _find_diagrams(self, text: str) -> list[str]:
        diagrams = []
        lines = text.split("\n")
        i = 0
        while i < len(lines):
            if re.match(r"^\s*\+-+", lines[i]):
                start = i
                while i < len(lines) and (re.match(r"^\s*[|+]", lines[i]) or not lines[i].strip()):
                    i += 1
                if i - start >= 3:
                    diagrams.append("\n".join(lines[start:i]))
            i += 1
        return diagrams

    def _parse_diagram(self, diagram: str) -> list[RFCField]:
        fields = []
        offset = 0
        lines = diagram.split("\n")

        for line in lines:
            if line.strip().startswith("|") and not line.strip().startswith("+-"):
                matches = self.FIELD_ROW_PATTERN.findall(line)
                for field_name in matches:
                    name = field_name.strip()
                    if not name or name == "|":
                        continue
                    char_width = len(field_name)
                    bits = max(1, (char_width * 32) // 70)
                    fields.append(RFCField(
                        name=name,
                        bits=bits,
                        offset_bits=offset,
                    ))
                    offset += bits

        return fields
