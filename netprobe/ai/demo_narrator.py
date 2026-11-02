"""Real-time AI narrator for Arsenal live demos."""

from __future__ import annotations

from rich.console import Console


class DemoNarrator:
    """Provide real-time narration during live Arsenal demos."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-5-5"):
        self.api_key = api_key
        self.model = model
        self.context: list[str] = []

    def narrate_phase(self, phase: str, details: dict, console: Console):
        narration = self._get_narration(phase, details)
        console.print(f"\n[bold cyan]> {narration}[/bold cyan]\n")
        self.context.append(f"{phase}: {narration}")

    def narrate_crash(self, crash: dict, console: Console):
        crash_type = crash.get("crash_type", "unknown")
        function = crash.get("function", "unknown")
        cwe = crash.get("cwe", "unknown")

        narration = (
            f"We just triggered a {crash_type} in {function}. "
            f"This maps to {cwe}. "
        )

        if crash.get("rce_potential"):
            narration += "This is potentially exploitable for remote code execution — "
            narration += "an attacker could crash your Wireshark by sending this packet on the wire."
        else:
            narration += "This is a denial of service — your IDS goes blind when it hits this packet."

        console.print(f"\n[bold red]> {narration}[/bold red]\n")

    def narrate_summary(self, stats: dict, console: Console):
        crashes = stats.get("unique_crashes", 0)
        execs = stats.get("executions", 0)
        rate = stats.get("execs_per_sec", 0)

        lines = [
            f"In {execs:,} executions at {rate:.0f}/sec, we found {crashes} unique crashes.",
        ]

        if crashes > 0:
            lines.append("Each of these is a potential CVE waiting to be filed.")
            lines.append("The tools you trust to protect your network just became the attack vector.")

        for line in lines:
            console.print(f"[bold cyan]> {line}[/bold cyan]")

    def _get_narration(self, phase: str, details: dict) -> str:
        narrations = {
            "recon": (
                f"Scanning {details.get('parser_count', '3000+')} protocol parsers. "
                f"Each one is hand-written C code that parses untrusted network input. "
                f"We're looking for the ones OSS-Fuzz can't reach."
            ),
            "audit": (
                f"Found {details.get('finding_count', 0)} dangerous code patterns — "
                f"unchecked memcpy, integer overflows, recursive calls without depth limits. "
                f"These are the exact patterns behind real CVEs."
            ),
            "fuzz": (
                f"Now fuzzing {details.get('protocol', 'the target protocol')} with "
                f"grammar-aware mutations. We extracted the protocol structure from the "
                f"dissector source code and are generating packets that exercise deep parser paths."
            ),
            "triage": (
                f"Triaging {details.get('crash_count', 0)} crashes — deduplicating by stack hash, "
                f"classifying CWE, estimating exploitability. "
                f"Each unique crash gets a CVSS score and exploit assessment."
            ),
            "report": (
                "Generating CVE-ready reports with reproduction steps, "
                "ASAN traces, and vendor-specific templates. "
                "Ready for responsible disclosure."
            ),
        }
        return narrations.get(phase, f"Phase: {phase}")
