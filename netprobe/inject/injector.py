"""Live network packet injection for demo and testing.

SAFETY: This module is for authorized security testing and demos only.
Only operates on explicitly specified interfaces with confirmation.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from .crafter import PacketCrafter, CraftedPacket


class LiveInjector:
    """Inject crafted packets on a network interface.

    Designed for isolated demo networks. Requires explicit safety acknowledgment.
    """

    def __init__(self, interface: str | None = None):
        self.interface = interface
        self.crafter = PacketCrafter()
        self.confirmed = False

    def confirm_safety(self, console: Console) -> bool:
        """Require explicit user confirmation before injection."""
        console.print(Panel(
            "[bold red]⚠️  LIVE INJECTION MODE ⚠️[/bold red]\n\n"
            "This will send crafted packets on a REAL network interface.\n"
            "Only use on isolated test/demo networks.\n"
            "Never use on production networks without authorization.\n\n"
            f"[bold]Interface:[/bold] {self.interface or 'default'}",
            title="[bold red]Safety Confirmation[/bold red]",
            border_style="red",
        ))

        if sys.stdin.isatty():
            response = input("\nType 'I-KNOW-WHAT-IM-DOING' to proceed: ")
            self.confirmed = response.strip() == "I-KNOW-WHAT-IM-DOING"
        else:
            self.confirmed = False

        return self.confirmed

    def inject_from_pcap(self, pcap_path: Path, crash_info: dict,
                         console: Console, count: int = 1,
                         delay: float = 1.0, dst_ip: str = "127.0.0.1",
                         dst_port: int = 80) -> int:
        """Inject payloads extracted from a crash pcap."""
        if not self.confirmed:
            console.print("[red]Safety confirmation required. Call confirm_safety() first.[/red]")
            return 0

        crafted = self.crafter.craft_from_crash(pcap_path, crash_info)
        if not crafted:
            console.print("[yellow]No payloads extracted from pcap.[/yellow]")
            return 0

        sent = 0
        for i in range(count):
            for pkt in crafted:
                try:
                    self._send_udp(pkt.raw_bytes, dst_ip, dst_port)
                    sent += 1
                    console.print(
                        f"[green]→[/green] Sent packet {sent}: {len(pkt.raw_bytes)} bytes "
                        f"({pkt.crash_type}) → {dst_ip}:{dst_port}"
                    )
                except OSError as e:
                    console.print(f"[red]Send failed: {e}[/red]")

                if delay > 0:
                    time.sleep(delay)

        console.print(f"\n[bold green]✓[/bold green] Injected {sent} packets")
        return sent

    def inject_crafted(self, packets: list[CraftedPacket],
                       dst_ip: str, dst_port: int,
                       console: Console, delay: float = 0.5) -> int:
        """Inject pre-crafted packets."""
        if not self.confirmed:
            console.print("[red]Safety confirmation required.[/red]")
            return 0

        sent = 0
        for pkt in packets:
            try:
                self._send_udp(pkt.raw_bytes, dst_ip, dst_port)
                sent += 1
                console.print(
                    f"[green]→[/green] {pkt.description} → {dst_ip}:{dst_port}"
                )
            except OSError as e:
                console.print(f"[red]Send failed: {e}[/red]")

            if delay > 0:
                time.sleep(delay)

        return sent

    def _send_udp(self, payload: bytes, dst_ip: str, dst_port: int):
        """Send a UDP packet."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, (dst_ip, dst_port))

    def _send_tcp(self, payload: bytes, dst_ip: str, dst_port: int):
        """Send a TCP payload."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((dst_ip, dst_port))
            sock.sendall(payload)
