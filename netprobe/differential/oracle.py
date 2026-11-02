"""Differential fuzzing oracle — run same input through multiple tools."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box


@dataclass
class ToolResult:
    tool: str
    return_code: int
    crashed: bool
    output_lines: list[str]
    protocols_detected: set[str]
    duration: float
    error: str = ""


@dataclass
class DiffResult:
    pcap_path: str
    tool_results: list[ToolResult]
    has_crash_divergence: bool = False
    has_parse_divergence: bool = False
    crash_tools: list[str] = field(default_factory=list)
    protocol_disagreements: list[dict] = field(default_factory=list)


TOOL_COMMANDS = {
    "tshark": {
        "cmd": ["tshark", "-r", "{pcap}", "-T", "fields", "-e", "frame.protocols"],
        "protocol_field": True,
    },
    "tcpdump": {
        "cmd": ["tcpdump", "-r", "{pcap}", "-nn", "-v"],
        "protocol_field": False,
    },
    "suricata": {
        "cmd": ["suricata", "-r", "{pcap}", "-l", "{logdir}", "--set", "outputs.0.fast.enabled=yes"],
        "protocol_field": False,
    },
}


class DifferentialOracle:
    """Run the same pcap through multiple tools and compare results."""

    def __init__(self, tools: list[str] | None = None, timeout: float = 15.0):
        self.tools = tools or ["tshark", "tcpdump"]
        self.timeout = timeout
        self.available_tools = self._detect_tools()

    def _detect_tools(self) -> dict[str, Path]:
        found = {}
        for tool in self.tools:
            binary = tool.split()[0] if " " in tool else tool
            path = shutil.which(binary)
            if path:
                found[tool] = Path(path)
        return found

    def test_pcap(self, pcap_path: Path) -> DiffResult:
        """Run a pcap through all available tools and compare."""
        results = []

        for tool_name, binary in self.available_tools.items():
            result = self._run_tool(tool_name, binary, pcap_path)
            results.append(result)

        diff = DiffResult(
            pcap_path=str(pcap_path),
            tool_results=results,
        )

        crashed = [r for r in results if r.crashed]
        not_crashed = [r for r in results if not r.crashed]
        if crashed and not_crashed:
            diff.has_crash_divergence = True
            diff.crash_tools = [r.tool for r in crashed]

        all_protocols = {}
        for r in results:
            if r.protocols_detected:
                all_protocols[r.tool] = r.protocols_detected

        if len(all_protocols) >= 2:
            tool_names = list(all_protocols.keys())
            for i in range(len(tool_names)):
                for j in range(i + 1, len(tool_names)):
                    t1, t2 = tool_names[i], tool_names[j]
                    p1, p2 = all_protocols[t1], all_protocols[t2]
                    only_in_1 = p1 - p2
                    only_in_2 = p2 - p1
                    if only_in_1 or only_in_2:
                        diff.has_parse_divergence = True
                        diff.protocol_disagreements.append({
                            "tool_a": t1,
                            "tool_b": t2,
                            "only_in_a": list(only_in_1),
                            "only_in_b": list(only_in_2),
                        })

        return diff

    def _run_tool(self, tool_name: str, binary: Path, pcap_path: Path) -> ToolResult:
        config = TOOL_COMMANDS.get(tool_name, {"cmd": [tool_name, "-r", "{pcap}"], "protocol_field": False})
        cmd = [c.replace("{pcap}", str(pcap_path)).replace("{logdir}", "/tmp/netprobe_diff")
               for c in config["cmd"]]

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout,
                env={**os.environ},
            )
            return_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
            crashed = return_code != 0 and return_code not in (0, 1)
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool_name, return_code=-1, crashed=False,
                output_lines=[], protocols_detected=set(),
                duration=self.timeout, error="timeout",
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool_name, return_code=-1, crashed=False,
                output_lines=[], protocols_detected=set(),
                duration=0, error="not found",
            )

        duration = time.monotonic() - start
        lines = stdout.strip().split("\n") if stdout.strip() else []

        protocols = set()
        if config.get("protocol_field") and lines:
            for line in lines:
                for proto in line.split(":"):
                    proto = proto.strip()
                    if proto:
                        protocols.add(proto.lower())

        return ToolResult(
            tool=tool_name,
            return_code=return_code,
            crashed=crashed,
            output_lines=lines[:50],
            protocols_detected=protocols,
            duration=duration,
            error=stderr[:500] if crashed else "",
        )

    def run_campaign(self, pcap_dir: Path, console: Console) -> list[DiffResult]:
        """Run differential testing on all pcaps in a directory."""
        pcaps = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))
        if not pcaps:
            console.print("[yellow]No pcap files found.[/yellow]")
            return []

        console.print(f"[bold]Differential testing {len(pcaps)} pcaps across "
                      f"{list(self.available_tools.keys())}[/bold]\n")

        divergences = []
        for pcap in pcaps:
            result = self.test_pcap(pcap)
            if result.has_crash_divergence or result.has_parse_divergence:
                divergences.append(result)
                if result.has_crash_divergence:
                    console.print(f"[bold red]💥 CRASH DIVERGENCE:[/bold red] {pcap.name} — "
                                  f"crashed in {result.crash_tools}")
                if result.has_parse_divergence:
                    console.print(f"[bold yellow]⚠ PARSE DIVERGENCE:[/bold yellow] {pcap.name}")
                    for d in result.protocol_disagreements:
                        console.print(f"  {d['tool_a']} sees {d['only_in_a']}, "
                                      f"{d['tool_b']} sees {d['only_in_b']}")

        console.print(f"\n[bold]{len(pcaps)} pcaps tested, "
                      f"{len(divergences)} divergences found[/bold]")
        return divergences
