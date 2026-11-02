"""NetProbe CLI — Who Watches the Watchmen?"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

console = Console()

BANNER = r"""
[bold red]
 _   _      _   ____            _
| \ | | ___| |_|  _ \ _ __ ___ | |__   ___
|  \| |/ _ \ __| |_) | '__/ _ \| '_ \ / _ \
| |\  |  __/ |_|  __/| | | (_) | |_) |  __/
|_| \_|\___|\__|_|   |_|  \___/|_.__/ \___|
[/bold red]
[dim]Who Watches the Watchmen?[/dim]
[dim]Network Security Tool Vulnerability Hunter v1.0.0[/dim]
"""


@click.group()
@click.version_option(version="1.0.0", prog_name="netprobe")
def main():
    """NetProbe — Vulnerability hunter for network security tool protocol parsers.

    Targets: Wireshark, Suricata, tcpdump, Zeek, Snort.
    """
    pass


@main.command()
@click.option("--source", "-s", type=click.Path(exists=True), required=True,
              help="Path to target tool source code")
@click.option("--target", "-t", default="wireshark",
              type=click.Choice(["wireshark", "suricata", "tcpdump", "zeek", "snort"]),
              help="Target tool to analyze")
@click.option("--top", "-n", default=50, help="Number of top-risk parsers to show")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
def recon(source: str, target: str, top: int, output: str | None):
    """Reconnaissance — map parsers, score risk, find fuzzing gaps."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n[bold]Source:[/bold] {source}",
        title="[bold cyan]Recon Mode[/bold cyan]",
        border_style="cyan",
    ))

    from netprobe.recon.source_mapper import SourceMapper
    from netprobe.recon.complexity_scorer import ComplexityScorer
    from netprobe.recon.risk_ranker import RiskRanker

    source_path = Path(source)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Mapping parsers...", total=4)

        mapper = SourceMapper(source_path, target)
        parsers = mapper.map_all()
        progress.update(task, advance=1, description=f"Found {len(parsers)} parsers")

        progress.update(task, description="Scoring complexity...")
        scorer = ComplexityScorer()
        scored = scorer.score_all(parsers)
        progress.update(task, advance=1)

        progress.update(task, description="Analyzing risk...")
        ranker = RiskRanker()
        ranked = ranker.rank(scored)
        progress.update(task, advance=1)

        progress.update(task, description="Done!", advance=1)

    table = Table(
        title=f"[bold]Top {top} High-Risk Parsers[/bold]",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Rank", style="bold", width=5)
    table.add_column("Parser", style="cyan")
    table.add_column("Protocol", style="green")
    table.add_column("Risk Score", style="red bold", justify="right")
    table.add_column("Lines", justify="right")
    table.add_column("Dangerous Calls", justify="right", style="yellow")
    table.add_column("Flags", style="magenta")

    for i, p in enumerate(ranked[:top], 1):
        flags = []
        if p.get("no_fuzz_coverage"):
            flags.append("NO-FUZZ")
        if p.get("recently_modified"):
            flags.append("RECENT")
        if p.get("has_recursion"):
            flags.append("RECURSIVE")
        if p.get("has_unchecked_alloc"):
            flags.append("ALLOC")

        table.add_row(
            str(i),
            p["filename"],
            p.get("protocol", "unknown"),
            f"{p['risk_score']:.1f}",
            str(p.get("lines", 0)),
            str(p.get("dangerous_calls", 0)),
            " ".join(flags) if flags else "-",
        )

    console.print(table)
    console.print(f"\n[bold green]✓[/bold green] Recon complete. {len(parsers)} parsers mapped, "
                  f"top {min(top, len(ranked))} ranked by risk.")

    if output:
        import json
        out_path = Path(output)
        out_path.write_text(json.dumps(ranked[:top], indent=2))
        console.print(f"[dim]Results saved to {output}[/dim]")


@main.command()
@click.option("--source", "-s", type=click.Path(exists=True), required=True,
              help="Path to target tool source code")
@click.option("--target", "-t", default="wireshark",
              type=click.Choice(["wireshark", "suricata", "tcpdump", "zeek", "snort"]))
@click.option("--top", "-n", default=20, help="Number of top parsers to audit")
@click.option("--output", "-o", type=click.Path(), help="Output file (SARIF/JSON)")
def audit(source: str, target: str, top: int, output: str | None):
    """Static analysis — find dangerous patterns in parser source code."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Static Audit[/bold] — scanning for dangerous code patterns",
        title="[bold yellow]Audit Mode[/bold yellow]",
        border_style="yellow",
    ))

    from netprobe.audit.pattern_scanner import PatternScanner
    from netprobe.recon.source_mapper import SourceMapper

    source_path = Path(source)
    mapper = SourceMapper(source_path, target)
    parsers = mapper.map_all()

    scanner = PatternScanner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(parsers))
        all_findings = []
        for parser in parsers:
            findings = scanner.scan_file(parser["path"])
            for f in findings:
                f["parser"] = parser["filename"]
            all_findings.extend(findings)
            progress.update(task, advance=1,
                            description=f"Scanning... ({len(all_findings)} findings)")

    all_findings.sort(key=lambda x: x.get("severity_score", 0), reverse=True)

    table = Table(
        title=f"[bold]Audit Findings — {len(all_findings)} dangerous patterns[/bold]",
        box=box.ROUNDED,
    )
    table.add_column("#", width=4)
    table.add_column("Parser", style="cyan")
    table.add_column("Line", justify="right")
    table.add_column("Pattern", style="red")
    table.add_column("Severity", justify="center")
    table.add_column("Detail", style="dim", max_width=50)

    for i, f in enumerate(all_findings[:50], 1):
        sev = f.get("severity_score", 0)
        sev_style = "red bold" if sev >= 8 else "yellow" if sev >= 5 else "dim"
        table.add_row(
            str(i),
            f["parser"],
            str(f.get("line", "?")),
            f["pattern_name"],
            f"[{sev_style}]{sev:.0f}/10[/{sev_style}]",
            f.get("detail", ""),
        )

    console.print(table)
    console.print(f"\n[bold green]✓[/bold green] Audit complete. "
                  f"{len(all_findings)} dangerous patterns found.")


@main.command()
@click.option("--target", "-t", default="wireshark",
              type=click.Choice(["wireshark", "suricata", "tcpdump", "zeek", "snort"]))
@click.option("--binary", "-b", type=click.Path(exists=True),
              help="Path to target binary (e.g., tshark)")
@click.option("--protocol", "-p", multiple=True, help="Protocol(s) to fuzz")
@click.option("--duration", "-d", default=3600, help="Fuzzing duration in seconds")
@click.option("--cores", "-c", default=1, help="Parallel fuzzing cores")
@click.option("--corpus", type=click.Path(), default="corpus/seeds", help="Seed corpus directory")
@click.option("--crash-dir", type=click.Path(), default="corpus/crashes", help="Crash output dir")
@click.option("--decode-as", "decode_as", help="Force dissector (e.g., 'tcp.port==8888,http')")
@click.option("--timeout", default=10.0, help="Per-execution timeout (seconds)")
@click.option("--mutators", "-m", multiple=True,
              default=["bitflip", "overflow", "magic", "structure"],
              help="Mutation strategies to use")
def fuzz(target: str, binary: str | None, protocol: tuple, duration: int,
         cores: int, corpus: str, crash_dir: str, decode_as: str | None,
         timeout: float, mutators: tuple):
    """Fuzz — mutate protocol packets and find crashes."""
    console.print(BANNER)

    protocols_str = ", ".join(protocol) if protocol else "all"
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Binary:[/bold] {binary or 'auto-detect'}\n"
        f"[bold]Protocols:[/bold] {protocols_str}\n"
        f"[bold]Duration:[/bold] {duration}s\n"
        f"[bold]Cores:[/bold] {cores}\n"
        f"[bold]Mutators:[/bold] {', '.join(mutators)}",
        title="[bold red]Fuzz Mode[/bold red]",
        border_style="red",
    ))

    from netprobe.core.campaign import FuzzCampaign

    crash_path = Path(crash_dir)
    crash_path.mkdir(parents=True, exist_ok=True)

    campaign = FuzzCampaign(
        target=target,
        binary_path=Path(binary) if binary else None,
        protocols=list(protocol),
        duration=duration,
        cores=cores,
        corpus_dir=Path(corpus),
        crash_dir=crash_path,
        decode_as=decode_as,
        timeout=timeout,
        mutator_names=list(mutators),
    )
    campaign.run(console)


@main.command()
@click.option("--crash-dir", type=click.Path(exists=True), default="corpus/crashes",
              help="Directory containing crash inputs")
@click.option("--binary", "-b", type=click.Path(exists=True), help="Target binary for replay")
@click.option("--minimize/--no-minimize", default=True, help="Minimize crash inputs")
@click.option("--output", "-o", type=click.Path(), help="Output directory for reports")
def triage(crash_dir: str, binary: str | None, minimize: bool, output: str | None):
    """Triage — deduplicate, minimize, classify crashes."""
    console.print(BANNER)
    console.print(Panel(
        "[bold]Crash Triage Pipeline[/bold]",
        title="[bold magenta]Triage Mode[/bold magenta]",
        border_style="magenta",
    ))

    from netprobe.triage.crash_detector import CrashDetector
    from netprobe.triage.deduplicator import Deduplicator
    from netprobe.triage.classifier import CWEClassifier

    crash_path = Path(crash_dir)
    crashes = list(crash_path.glob("*.pcap")) + list(crash_path.glob("*.pcapng"))

    if not crashes:
        console.print("[yellow]No crash files found.[/yellow]")
        return

    console.print(f"Found [bold]{len(crashes)}[/bold] crash files")

    detector = CrashDetector(binary_path=Path(binary) if binary else None)
    deduper = Deduplicator()
    classifier = CWEClassifier()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Replaying crashes...", total=len(crashes))
        crash_reports = []
        for crash_file in crashes:
            report = detector.replay(crash_file)
            if report:
                crash_reports.append(report)
            progress.update(task, advance=1)

    unique = deduper.deduplicate(crash_reports)
    console.print(f"[bold]{len(crash_reports)}[/bold] crashes → "
                  f"[bold green]{len(unique)}[/bold green] unique")

    for report in unique:
        classifier.classify(report)

    table = Table(title="[bold]Unique Crashes[/bold]", box=box.ROUNDED)
    table.add_column("ID", width=8)
    table.add_column("File", style="cyan")
    table.add_column("CWE", style="red")
    table.add_column("Severity", justify="center")
    table.add_column("Crash Type")
    table.add_column("Function", style="yellow")

    for r in unique:
        sev = r.get("severity", "unknown")
        sev_style = "red bold" if sev == "high" else "yellow" if sev == "medium" else "dim"
        table.add_row(
            r.get("crash_id", "?")[:8],
            r.get("filename", "?"),
            r.get("cwe", "?"),
            f"[{sev_style}]{sev}[/{sev_style}]",
            r.get("crash_type", "?"),
            r.get("function", "?"),
        )

    console.print(table)


@main.command()
@click.option("--crash-id", required=True, help="Crash ID to generate report for")
@click.option("--crash-dir", type=click.Path(exists=True), default="corpus/crashes")
@click.option("--format", "fmt", type=click.Choice(["cve", "sarif", "markdown"]), default="cve")
@click.option("--output", "-o", type=click.Path())
def report(crash_id: str, crash_dir: str, fmt: str, output: str | None):
    """Generate CVE-ready vulnerability reports."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Generating {fmt.upper()} report for crash {crash_id}[/bold]",
        title="[bold green]Report Mode[/bold green]",
        border_style="green",
    ))

    from netprobe.reporters.cve_report import CVEReportGenerator
    from netprobe.reporters.markdown_report import MarkdownReportGenerator

    if fmt == "cve":
        gen = CVEReportGenerator()
    else:
        gen = MarkdownReportGenerator()

    report_text = gen.generate(crash_id, Path(crash_dir))

    if output:
        Path(output).write_text(report_text)
        console.print(f"[bold green]✓[/bold green] Report saved to {output}")
    else:
        console.print(report_text)


@main.command()
@click.option("--target", "-t", default="wireshark")
@click.option("--binary", "-b", type=click.Path(exists=True))
@click.option("--protocol", "-p", help="Protocol to demo (or 'interactive' for audience choice)")
def demo(target: str, binary: str | None, protocol: str | None):
    """Live demo mode for Arsenal presentations."""
    console.print(BANNER)
    console.print(Panel(
        "[bold red]🔴 LIVE DEMO MODE[/bold red]\n\n"
        "Full pipeline: recon → audit → fuzz → triage → report\n"
        "Designed for Black Hat Arsenal stage demos",
        title="[bold red]Arsenal Demo[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    if protocol == "interactive" or not protocol:
        from netprobe.core.target_registry import BUILTIN_TARGETS
        console.print("\n[bold]Pick a protocol to fuzz live:[/bold]\n")
        protocols = [
            "dns", "http", "tls", "mqtt", "coap", "modbus", "dnp3",
            "smb2", "diameter", "gtp", "quic", "bgp", "dcerpc",
        ]
        for i, p in enumerate(protocols, 1):
            console.print(f"  [{i}] {p.upper()}")
        console.print()
        choice = click.prompt("Protocol number", type=int, default=1)
        protocol = protocols[min(choice, len(protocols)) - 1]

    console.print(f"\n[bold cyan]Target protocol: {protocol.upper()}[/bold cyan]\n")
    console.print("[bold]Phase 1: Static Analysis...[/bold]")
    time.sleep(1)
    console.print("[bold]Phase 2: Generating mutations...[/bold]")
    time.sleep(1)
    console.print("[bold red]Phase 3: Fuzzing...[/bold red]")
    console.print("[dim]Demo mode — connect to a real campaign with --binary[/dim]")


@main.command()
def targets():
    """List supported target tools."""
    console.print(BANNER)

    from netprobe.core.target_registry import list_targets

    table = Table(title="[bold]Supported Targets[/bold]", box=box.ROUNDED)
    table.add_column("Name", style="cyan bold")
    table.add_column("Language", style="green")
    table.add_column("Parser Pattern")
    table.add_column("Description", style="dim")

    for t in list_targets():
        table.add_row(t.name, t.language, t.parser_glob, t.description)

    console.print(table)


@main.command()
@click.option("--source", "-s", type=click.Path(exists=True), required=True,
              help="Path to target tool source code")
@click.option("--protocol", "-p", required=True, help="Protocol name (e.g., dns, http)")
@click.option("--output", "-o", type=click.Path(), default="grammars/extracted",
              help="Output directory for grammar + pcaps")
@click.option("--count", "-n", default=50, help="Number of pcaps to generate")
def grammar(source: str, protocol: str, output: str, count: int):
    """Extract protocol grammar from source and synthesize pcaps."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Protocol Grammar Engine[/bold]\n"
        f"Source: {source}\nProtocol: {protocol}",
        title="[bold blue]Grammar Mode[/bold blue]",
        border_style="blue",
    ))

    from netprobe.grammar.extractor import GrammarExtractor
    from netprobe.grammar.grammar_model import grammar_to_template
    from netprobe.grammar.pcap_synthesizer import PcapSynthesizer

    extractor = GrammarExtractor()
    source_path = Path(source)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Extracting grammar...", total=3)

        grammars = extractor.extract_from_directory(source_path)
        matching = [g for g in grammars if g.short_name.lower() == protocol.lower()]
        if not matching:
            console.print(f"[red]No grammar found for protocol '{protocol}'.[/red]")
            console.print(f"[dim]Available: {', '.join(g.short_name for g in grammars[:20])}[/dim]")
            return
        grammar = matching[0]
        progress.update(task, advance=1, description=f"Found {grammar.field_count()} fields")

        template = grammar_to_template(grammar)
        progress.update(task, advance=1, description="Synthesizing pcaps...")

        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        synth = PcapSynthesizer()

        pcaps = synth.synthesize_mutated(template, count=count)
        for i, pcap_data in enumerate(pcaps):
            pcap_path = out_dir / f"{protocol}_gen_{i:04d}.pcap"
            synth.write_pcap(pcap_data, pcap_path)

        progress.update(task, advance=1)

    console.print(f"\n[bold green]✓[/bold green] Extracted {grammar.field_count()} fields, "
                  f"generated {count} pcaps in {output}")


@main.command()
@click.option("--pcap-dir", "-d", type=click.Path(exists=True), required=True,
              help="Directory of pcaps to test")
@click.option("--output", "-o", type=click.Path(), help="Output JSON report")
def diff(pcap_dir: str, output: str | None):
    """Differential fuzzing — run pcaps through multiple tools and find divergences."""
    console.print(BANNER)
    console.print(Panel(
        "[bold]Differential Oracle[/bold] — crash one tool but not another = real bug",
        title="[bold yellow]Diff Mode[/bold yellow]",
        border_style="yellow",
    ))

    from netprobe.differential.oracle import DifferentialOracle

    oracle = DifferentialOracle()
    results = oracle.run_campaign(Path(pcap_dir), console)

    if output:
        import json
        Path(output).write_text(json.dumps(results, indent=2, default=str))
        console.print(f"[dim]Results saved to {output}[/dim]")


@main.command()
@click.option("--pcap", "-p", type=click.Path(exists=True), required=True,
              help="Crash pcap to inject")
@click.option("--dst-ip", default="127.0.0.1", help="Destination IP")
@click.option("--dst-port", default=80, type=int, help="Destination port")
@click.option("--count", "-n", default=1, help="Number of injection rounds")
@click.option("--delay", default=1.0, type=float, help="Delay between packets (seconds)")
def inject(pcap: str, dst_ip: str, dst_port: int, count: int, delay: float):
    """Live injection — send crash-triggering packets on the wire."""
    console.print(BANNER)
    console.print(Panel(
        "[bold red]Live Packet Injection[/bold red]\n"
        "For authorized testing and Arsenal demos ONLY",
        title="[bold red]Inject Mode[/bold red]",
        border_style="red",
    ))

    from netprobe.inject.injector import LiveInjector

    injector = LiveInjector()
    if not injector.confirm_safety(console):
        console.print("[yellow]Injection cancelled.[/yellow]")
        return

    crash_info = {"crash_type": "unknown", "cwe": "unknown", "function": "unknown"}
    injector.inject_from_pcap(
        Path(pcap), crash_info, console,
        count=count, delay=delay, dst_ip=dst_ip, dst_port=dst_port,
    )


@main.command()
@click.option("--pcap", "-p", type=click.Path(exists=True), required=True,
              help="Crash pcap to weaponize")
@click.option("--binary", "-b", type=click.Path(exists=True),
              help="Target binary for minimization/stability testing")
@click.option("--output", "-o", type=click.Path(), default="output/weaponized",
              help="Output directory for PoC package")
def weaponize(pcap: str, binary: str | None, output: str):
    """Weaponize — minimize, stabilize, and package crash into disclosure-ready PoC."""
    console.print(BANNER)
    console.print(Panel(
        "[bold]Weaponized PoC Generator[/bold]\n"
        "Minimize → Stabilize → Package → Disclose",
        title="[bold magenta]Weaponize Mode[/bold magenta]",
        border_style="magenta",
    ))

    from netprobe.weaponize.generator import WeaponizedPcapGenerator

    gen = WeaponizedPcapGenerator()
    pcap_path = Path(pcap)
    out_dir = Path(output)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Minimizing...", total=3)

        binary_path = Path(binary) if binary else None
        minimized = gen.minimize(pcap_path, binary_path)
        progress.update(task, advance=1, description="Stabilizing...")

        if binary_path:
            stable, rate = gen.stabilize(minimized, binary_path)
            console.print(f"  Reproduction rate: [bold]{rate*100:.0f}%[/bold] "
                          f"({'stable' if stable else 'flaky'})")
        progress.update(task, advance=1, description="Packaging...")

        crash_info = {
            "crash_id": pcap_path.stem,
            "crash_type": "unknown",
            "cwe": "unknown",
            "function": "unknown",
        }
        pkg_dir = gen.package(minimized, crash_info, out_dir)
        progress.update(task, advance=1)

    console.print(f"\n[bold green]✓[/bold green] PoC package ready: {pkg_dir}")
    console.print("[dim]Contents: crash.pcap, reproduce.sh, Dockerfile, metadata.json, README.md[/dim]")


@main.command()
@click.option("--profile", "-p", default="enterprise",
              type=click.Choice(["enterprise", "ics", "isp", "iot"]),
              help="Traffic profile")
@click.option("--packets", "-n", default=1000, help="Number of packets")
@click.option("--output", "-o", type=click.Path(), default="output/honeypot.pcap",
              help="Output pcap file")
def honeypot(profile: str, packets: int, output: str):
    """Honeypot — generate traffic that crashes attacker tools."""
    console.print(BANNER)
    console.print(Panel(
        "[bold]Honeypot Traffic Generator[/bold]\n"
        "Embed parser triggers in realistic network traffic\n"
        "When attackers analyze this traffic, their tools crash",
        title="[bold green]Honeypot Mode[/bold green]",
        border_style="green",
    ))

    from netprobe.honeypot.generator import HoneypotTrafficGenerator

    gen = HoneypotTrafficGenerator(profile)
    gen.generate(Path(output), packets, console)


@main.command()
@click.option("--source", "-s", type=click.Path(exists=True), required=True,
              help="Parser source file to analyze")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
def ai(source: str, api_key: str | None):
    """AI analysis — use Claude to find vulnerabilities in parser code."""
    console.print(BANNER)
    console.print(Panel(
        "[bold]AI-Powered Vulnerability Analysis[/bold]\n"
        "Claude reads parser code and identifies exploitable patterns",
        title="[bold purple]AI Mode[/bold purple]",
        border_style="purple",
    ))

    if not api_key:
        console.print("[red]Set ANTHROPIC_API_KEY or pass --api-key[/red]")
        return

    from netprobe.ai.code_analyzer import AICodeAnalyzer

    analyzer = AICodeAnalyzer(api_key=api_key)
    findings = analyzer.analyze_file(Path(source), console)

    if not findings:
        console.print("[yellow]No vulnerabilities identified by AI.[/yellow]")
        return

    table = Table(title=f"[bold]AI Findings — {len(findings)}[/bold]", box=box.ROUNDED)
    table.add_column("#", width=4)
    table.add_column("Type", style="red")
    table.add_column("Severity")
    table.add_column("Confidence", justify="right")
    table.add_column("Description", max_width=50)
    table.add_column("Mutation Hint", style="cyan", max_width=40)

    for i, f in enumerate(findings, 1):
        sev_style = "red bold" if f.severity == "critical" else "yellow" if f.severity == "high" else "dim"
        table.add_row(
            str(i), f.vulnerability_type,
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f"{f.confidence:.0%}",
            f.description[:50], f.suggested_mutation[:40],
        )

    console.print(table)


@main.command()
@click.option("--results", "-r", type=click.Path(exists=True),
              help="Campaign results JSON file")
@click.option("--output", "-o", type=click.Path(), default="output/dashboard.html",
              help="Output HTML file")
def dashboard(results: str | None, output: str):
    """Generate an interactive HTML campaign dashboard."""
    console.print(BANNER)

    from netprobe.reporters.html_dashboard import DashboardGenerator
    import json

    if results:
        data = json.loads(Path(results).read_text())
    else:
        data = {"crashes": [], "stats": {}}

    gen = DashboardGenerator()
    out_path = gen.generate(data, Path(output))
    console.print(f"[bold green]✓[/bold green] Dashboard generated: {out_path}")


if __name__ == "__main__":
    main()
