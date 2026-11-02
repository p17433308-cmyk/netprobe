"""Fuzzing campaign orchestrator."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

from netprobe.mutators.engine import MutationEngine
from netprobe.harness.base import BaseHarness
from netprobe.coverage.corpus_manager import CorpusManager
from netprobe.triage.deduplicator import Deduplicator
from netprobe.triage.classifier import CWEClassifier


def _make_harness(target: str, binary_path: Path | None = None,
                  timeout: float = 10.0, decode_as: str | None = None) -> BaseHarness:
    if target == "wireshark":
        from netprobe.harness.wireshark import WiresharkHarness
        return WiresharkHarness(binary_path=binary_path, timeout=timeout, decode_as=decode_as)
    elif target == "tcpdump":
        from netprobe.harness.tcpdump import TcpdumpHarness
        return TcpdumpHarness(binary_path=binary_path, timeout=timeout)
    elif target == "suricata":
        from netprobe.harness.suricata import SuricataHarness
        return SuricataHarness(binary_path=binary_path, timeout=timeout)
    elif target == "zeek":
        from netprobe.harness.zeek import ZeekHarness
        return ZeekHarness(binary_path=binary_path, timeout=timeout)
    elif target == "snort":
        from netprobe.harness.snort import SnortHarness
        return SnortHarness(binary_path=binary_path, timeout=timeout)
    else:
        from netprobe.harness.wireshark import WiresharkHarness
        return WiresharkHarness(binary_path=binary_path, timeout=timeout, decode_as=decode_as)


class FuzzCampaign:
    def __init__(
        self,
        target: str = "wireshark",
        binary_path: Path | None = None,
        protocols: list[str] | None = None,
        duration: int = 3600,
        cores: int = 1,
        corpus_dir: Path = Path("corpus/seeds"),
        crash_dir: Path = Path("corpus/crashes"),
        decode_as: str | None = None,
        timeout: float = 10.0,
        mutator_names: list[str] | None = None,
    ):
        self.target = target
        self.binary_path = binary_path
        self.protocols = protocols or []
        self.duration = duration
        self.cores = cores
        self.corpus_dir = corpus_dir
        self.crash_dir = crash_dir
        self.decode_as = decode_as
        self.timeout = timeout
        self.mutator_names = mutator_names or ["bitflip", "overflow", "magic", "structure"]

        self.stats = {
            "executions": 0,
            "crashes": 0,
            "unique_crashes": 0,
            "timeouts": 0,
            "start_time": 0.0,
            "execs_per_sec": 0.0,
        }

    def run(self, console: Console):
        """Execute the fuzzing campaign."""
        harness = _make_harness(
            self.target,
            binary_path=self.binary_path,
            timeout=self.timeout,
            decode_as=self.decode_as,
        )

        console.print(f"\n[bold green]Target binary:[/bold green] {harness.binary_path}")
        console.print(f"[bold green]Version:[/bold green] {harness.get_version()}")

        engine = MutationEngine(self.mutator_names)
        deduper = Deduplicator()
        classifier = CWEClassifier()
        corpus = CorpusManager(self.corpus_dir)

        seeds = self._load_seeds()
        if not seeds:
            console.print("[yellow]No seed corpus found. Generating minimal pcaps...[/yellow]")
            seeds = [self._generate_minimal_pcap()]

        console.print(f"[bold]Seed corpus:[/bold] {len(seeds)} files ({corpus.size} in corpus)")
        console.print(f"[bold]Duration:[/bold] {self.duration}s")
        console.print(f"[bold]Mutators:[/bold] {', '.join(self.mutator_names)}\n")

        self.crash_dir.mkdir(parents=True, exist_ok=True)

        all_crashes: list[dict] = []
        self.stats["start_time"] = time.monotonic()
        end_time = self.stats["start_time"] + self.duration

        import random
        rng = random.Random()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[red]Fuzzing...", total=self.duration,
            )

            while time.monotonic() < end_time:
                entry = corpus.select(rng)
                if entry:
                    seed_data = entry.path.read_bytes()
                else:
                    seed = seeds[self.stats["executions"] % len(seeds)]
                    seed_data = seed.read_bytes()

                mutations = engine.mutate(seed_data, count=10)

                for mutated in mutations:
                    if time.monotonic() >= end_time:
                        break

                    tmp_pcap = self.crash_dir / f"tmp_mutation.pcap"
                    tmp_pcap.write_bytes(mutated)

                    result = harness.execute(tmp_pcap)
                    self.stats["executions"] += 1

                    if result.timed_out:
                        self.stats["timeouts"] += 1

                    if not result.crashed and not result.timed_out:
                        corpus.add(mutated, found_coverage=False)

                    if result.crashed:
                        self.stats["crashes"] += 1
                        crash_name = f"crash_{self.stats['crashes']:06d}.pcap"
                        crash_path = self.crash_dir / crash_name
                        shutil.copy2(tmp_pcap, crash_path)
                        corpus.add(mutated, found_coverage=True, source="crash")

                        crash_report = {
                            "crash_id": f"{self.stats['crashes']:06d}",
                            "filename": crash_name,
                            "pcap_path": str(crash_path),
                            "crash_type": result.crash_type or "unknown",
                            "function": result.crash_function,
                            "stack_trace": result.stack_trace or [],
                            "return_code": result.return_code,
                            "asan_report": result.asan_report,
                        }
                        classifier.classify(crash_report)
                        all_crashes.append(crash_report)

                        console.print(
                            f"[bold red]💥 CRASH #{self.stats['crashes']}[/bold red] "
                            f"[cyan]{crash_report.get('cwe', '?')}[/cyan] "
                            f"{crash_report.get('crash_type', '?')} "
                            f"in [yellow]{crash_report.get('function', '?')}[/yellow]"
                        )

                    tmp_pcap.unlink(missing_ok=True)

                elapsed = time.monotonic() - self.stats["start_time"]
                self.stats["execs_per_sec"] = self.stats["executions"] / max(elapsed, 0.01)
                progress.update(
                    task,
                    completed=min(int(elapsed), self.duration),
                    description=(
                        f"[red]Fuzzing... "
                        f"{self.stats['execs_per_sec']:.0f} exec/s | "
                        f"{self.stats['crashes']} crashes"
                    ),
                )

        unique = deduper.deduplicate(all_crashes)
        self.stats["unique_crashes"] = len(unique)

        self._print_summary(console, unique)

        report_path = self.crash_dir / "campaign_report.json"
        report_path.write_text(json.dumps({
            "stats": self.stats,
            "unique_crashes": unique,
        }, indent=2, default=str))
        console.print(f"\n[dim]Report saved to {report_path}[/dim]")

    def _load_seeds(self) -> list[Path]:
        if not self.corpus_dir.exists():
            return []
        seeds = list(self.corpus_dir.glob("*.pcap")) + list(self.corpus_dir.glob("*.pcapng"))
        return seeds

    def _generate_minimal_pcap(self) -> Path:
        """Generate a minimal valid pcap file."""
        import struct
        header = struct.pack("<IHHiIII",
            0xa1b2c3d4,  # magic
            2, 4,         # version
            0,            # timezone
            0,            # sigfigs
            65535,        # snaplen
            1,            # ethernet
        )
        pkt_data = bytes(64)
        pkt_header = struct.pack("<IIII", 0, 0, len(pkt_data), len(pkt_data))

        minimal = self.corpus_dir
        minimal.mkdir(parents=True, exist_ok=True)
        path = minimal / "minimal.pcap"
        path.write_bytes(header + pkt_header + pkt_data)
        return path

    def _print_summary(self, console: Console, unique_crashes: list[dict]):
        elapsed = time.monotonic() - self.stats["start_time"]

        table = Table(title="[bold]Campaign Summary[/bold]", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Duration", f"{elapsed:.0f}s")
        table.add_row("Total Executions", f"{self.stats['executions']:,}")
        table.add_row("Exec/sec", f"{self.stats['execs_per_sec']:.1f}")
        table.add_row("Total Crashes", f"[red]{self.stats['crashes']}[/red]")
        table.add_row("Unique Crashes", f"[bold red]{len(unique_crashes)}[/bold red]")
        table.add_row("Timeouts", f"{self.stats['timeouts']}")

        console.print(table)

        if unique_crashes:
            crash_table = Table(title="[bold red]Unique Crashes[/bold red]", box=box.ROUNDED)
            crash_table.add_column("ID", width=8)
            crash_table.add_column("CWE", style="red")
            crash_table.add_column("Type")
            crash_table.add_column("Function", style="yellow")
            crash_table.add_column("Severity", justify="center")
            crash_table.add_column("CVSS", justify="right")
            crash_table.add_column("RCE?", justify="center")

            for c in unique_crashes:
                sev = c.get("severity", "?")
                sev_style = "red bold" if sev == "high" else "yellow" if sev == "medium" else "dim"
                rce = "[red bold]YES[/red bold]" if c.get("rce_potential") else "no"
                crash_table.add_row(
                    str(c.get("crash_id", "?"))[:8],
                    c.get("cwe", "?"),
                    c.get("crash_type", "?"),
                    c.get("function", "?"),
                    f"[{sev_style}]{sev}[/{sev_style}]",
                    f"{c.get('cvss_estimate', 0):.1f}",
                    rce,
                )

            console.print(crash_table)
