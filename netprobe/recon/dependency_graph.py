"""Parser call graph and protocol encapsulation chain analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParserNode:
    name: str
    file_path: str
    calls: list[str] = field(default_factory=list)
    called_by: list[str] = field(default_factory=list)
    protocols_handled: list[str] = field(default_factory=list)


class DependencyGraph:
    """Build a call graph of protocol parsers/dissectors."""

    CALL_PATTERNS = [
        re.compile(r'call_dissector\s*\(\s*(\w+)'),
        re.compile(r'dissector_try_uint\s*\(\s*(\w+)'),
        re.compile(r'find_dissector\s*\(\s*"(\w+)"'),
        re.compile(r'register_dissector\s*\(\s*"(\w+)"'),
    ]

    HANDOFF_PATTERN = re.compile(r'create_dissector_handle\s*\(\s*(\w+)')

    def build_from_directory(self, source_dir: str | Path, glob: str = "epan/dissectors/packet-*.c") -> dict[str, ParserNode]:
        path = Path(source_dir)
        nodes: dict[str, ParserNode] = {}

        for f in path.glob(glob):
            node = self._analyze_file(f)
            if node:
                nodes[node.name] = node

        for name, node in nodes.items():
            for callee in node.calls:
                if callee in nodes:
                    nodes[callee].called_by.append(name)

        return nodes

    def find_chains(self, nodes: dict[str, ParserNode], max_depth: int = 10) -> list[list[str]]:
        chains = []
        for name, node in nodes.items():
            if not node.called_by:
                chain = self._walk_chain(name, nodes, max_depth, set())
                if len(chain) > 1:
                    chains.append(chain)
        chains.sort(key=len, reverse=True)
        return chains

    def _analyze_file(self, file_path: Path) -> ParserNode | None:
        try:
            content = file_path.read_text(errors="replace")
        except Exception:
            return None

        name = file_path.stem.replace("packet-", "")
        calls = set()
        protocols = set()

        for pat in self.CALL_PATTERNS:
            for match in pat.finditer(content):
                calls.add(match.group(1))

        for match in re.finditer(r'proto_register_protocol\s*\([^,]+,\s*"([^"]+)"', content):
            protocols.add(match.group(1))

        return ParserNode(
            name=name,
            file_path=str(file_path),
            calls=list(calls),
            protocols_handled=list(protocols),
        )

    def _walk_chain(self, name: str, nodes: dict[str, ParserNode],
                    max_depth: int, visited: set) -> list[str]:
        if name in visited or max_depth <= 0 or name not in nodes:
            return [name]
        visited.add(name)
        chain = [name]
        for callee in nodes[name].calls:
            if callee in nodes and callee not in visited:
                sub = self._walk_chain(callee, nodes, max_depth - 1, visited)
                if len(sub) > len(chain) - 1:
                    chain = [name] + sub
        return chain
