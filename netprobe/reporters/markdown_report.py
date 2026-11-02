"""Human-readable Markdown campaign reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


class MarkdownReportGenerator:
    """Generate Markdown reports from campaign or crash data."""

    def generate(self, crash_id: str, crash_dir: Path) -> str:
        import json
        report_file = crash_dir / "campaign_report.json"
        crashes = []
        if report_file.exists():
            data = json.loads(report_file.read_text())
            crashes = data.get("unique_crashes", [])

        target_crash = None
        for c in crashes:
            if str(c.get("crash_id", "")).startswith(crash_id):
                target_crash = c
                break

        if not target_crash:
            return f"# Crash {crash_id}\n\nNo data found for crash ID: {crash_id}"

        lines = [
            f"# Vulnerability Report — {crash_id}",
            f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"\n## Summary\n",
            f"- **Crash Type:** {target_crash.get('crash_type', 'unknown')}",
            f"- **CWE:** {target_crash.get('cwe', 'unknown')}",
            f"- **Function:** `{target_crash.get('function', 'unknown')}`",
            f"- **Severity:** {target_crash.get('severity', 'unknown')}",
            f"- **CVSS Estimate:** {target_crash.get('cvss_estimate', 'N/A')}",
            f"- **RCE Potential:** {'Yes' if target_crash.get('rce_potential') else 'No'}",
            f"\n## Reproduction\n",
            f"```bash",
            f"tshark -r {target_crash.get('filename', 'crash.pcap')}",
            f"```",
            f"\n## ASAN Report\n",
            f"```",
            target_crash.get("asan_report", "No ASAN report available")[:3000],
            f"```",
            f"\n## Stack Trace\n",
        ]

        stack = target_crash.get("stack_trace", [])
        if stack:
            lines.append("```")
            for frame in stack[:20]:
                lines.append(f"  {frame}")
            lines.append("```")
        else:
            lines.append("No stack trace available.")

        return "\n".join(lines)
