"""Generate an interactive HTML dashboard for campaign results."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


class DashboardGenerator:
    """Generate a single-file HTML dashboard from campaign results."""

    def generate(self, results: dict, output_path: Path) -> Path:
        """Generate dashboard HTML from campaign results JSON."""
        crashes = results.get("crashes", [])
        stats = results.get("stats", {})
        total_exec = stats.get("total_executions", 0)
        total_crashes = stats.get("unique_crashes", len(crashes))
        duration = stats.get("duration_seconds", 0)
        coverage = stats.get("coverage_percent", 0)

        crash_rows = ""
        for c in crashes[:100]:
            rce = "Yes" if c.get("rce_potential") else "No"
            crash_rows += f"""
            <tr class="{'rce' if c.get('rce_potential') else ''}">
                <td>{c.get('crash_id', 'N/A')[:12]}</td>
                <td>{c.get('crash_type', 'unknown')}</td>
                <td>{c.get('cwe', 'N/A')}</td>
                <td>{c.get('cvss_estimate', 'N/A')}</td>
                <td>{rce}</td>
                <td>{c.get('function', 'unknown')}</td>
                <td>{c.get('pcap_file', 'N/A')}</td>
            </tr>"""

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for c in crashes:
            cvss = c.get("cvss_estimate", 0)
            if isinstance(cvss, (int, float)):
                if cvss >= 9.0:
                    severity_counts["critical"] += 1
                elif cvss >= 7.0:
                    severity_counts["high"] += 1
                elif cvss >= 4.0:
                    severity_counts["medium"] += 1
                else:
                    severity_counts["low"] += 1

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetProbe Dashboard</title>
<style>
:root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --green: #3fb950; --purple: #bc8cff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: var(--bg); color: var(--text); padding: 24px; }}
.header {{ text-align: center; padding: 32px 0; }}
.header h1 {{ font-size: 2.5em; background: linear-gradient(135deg, var(--red), var(--purple));
              -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.header p {{ color: var(--text-dim); font-size: 1.1em; margin-top: 8px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px; margin: 24px 0; }}
.stat {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: 12px; padding: 20px; text-align: center; }}
.stat .value {{ font-size: 2.2em; font-weight: 700; }}
.stat .label {{ color: var(--text-dim); margin-top: 4px; }}
.stat.critical .value {{ color: var(--red); }}
.stat.high .value {{ color: var(--orange); }}
.stat.rce .value {{ color: var(--purple); }}
.stat.exec .value {{ color: var(--accent); }}
.severity {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0; }}
.sev-box {{ padding: 16px; border-radius: 8px; text-align: center; }}
.sev-critical {{ background: rgba(248,81,73,0.15); border: 1px solid var(--red); }}
.sev-high {{ background: rgba(210,153,34,0.15); border: 1px solid var(--orange); }}
.sev-medium {{ background: rgba(88,166,255,0.15); border: 1px solid var(--accent); }}
.sev-low {{ background: rgba(63,185,80,0.15); border: 1px solid var(--green); }}
table {{ width: 100%; border-collapse: collapse; margin: 24px 0; }}
th {{ background: var(--surface); color: var(--accent); text-align: left;
     padding: 12px 16px; border-bottom: 2px solid var(--border); }}
td {{ padding: 10px 16px; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: rgba(88,166,255,0.05); }}
tr.rce {{ background: rgba(248,81,73,0.08); }}
.section {{ margin: 32px 0; }}
.section h2 {{ color: var(--accent); margin-bottom: 16px; }}
</style>
</head>
<body>
<div class="header">
    <h1>NetProbe</h1>
    <p>Who Watches the Watchmen? — Campaign Dashboard</p>
    <p style="color:var(--text-dim);font-size:0.9em">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>

<div class="stats">
    <div class="stat exec"><div class="value">{total_exec:,}</div><div class="label">Executions</div></div>
    <div class="stat critical"><div class="value">{total_crashes}</div><div class="label">Unique Crashes</div></div>
    <div class="stat rce"><div class="value">{sum(1 for c in crashes if c.get('rce_potential'))}</div><div class="label">RCE Potential</div></div>
    <div class="stat high"><div class="value">{coverage:.1f}%</div><div class="label">Code Coverage</div></div>
    <div class="stat"><div class="value" style="color:var(--green)">{duration:.0f}s</div><div class="label">Duration</div></div>
</div>

<div class="section">
    <h2>Severity Breakdown</h2>
    <div class="severity">
        <div class="sev-box sev-critical"><div style="font-size:2em;font-weight:700">{severity_counts['critical']}</div>Critical</div>
        <div class="sev-box sev-high"><div style="font-size:2em;font-weight:700">{severity_counts['high']}</div>High</div>
        <div class="sev-box sev-medium"><div style="font-size:2em;font-weight:700">{severity_counts['medium']}</div>Medium</div>
        <div class="sev-box sev-low"><div style="font-size:2em;font-weight:700">{severity_counts['low']}</div>Low</div>
    </div>
</div>

<div class="section">
    <h2>Crash Findings</h2>
    <table>
        <thead><tr>
            <th>ID</th><th>Type</th><th>CWE</th><th>CVSS</th><th>RCE</th><th>Function</th><th>Pcap</th>
        </tr></thead>
        <tbody>{crash_rows if crash_rows else '<tr><td colspan="7" style="text-align:center;color:var(--text-dim)">No crashes found yet — start a campaign!</td></tr>'}</tbody>
    </table>
</div>

<div style="text-align:center;padding:32px;color:var(--text-dim)">
    NetProbe v1.0.0 — Who Watches the Watchmen?
</div>
</body>
</html>"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html)
        return output_path
