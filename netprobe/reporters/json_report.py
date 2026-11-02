"""Machine-readable JSON campaign reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class JsonReportGenerator:
    """Generate comprehensive JSON reports from campaign data."""

    def generate(self, campaign_data: dict, output_path: Path | None = None) -> str:
        report = {
            "tool": "NetProbe",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_executions": campaign_data.get("stats", {}).get("executions", 0),
                "total_crashes": campaign_data.get("stats", {}).get("crashes", 0),
                "unique_crashes": campaign_data.get("stats", {}).get("unique_crashes", 0),
                "duration_seconds": campaign_data.get("stats", {}).get("duration", 0),
                "execs_per_second": campaign_data.get("stats", {}).get("execs_per_sec", 0),
            },
            "crashes": campaign_data.get("unique_crashes", []),
            "audit_findings": campaign_data.get("audit_findings", []),
            "coverage": campaign_data.get("coverage", {}),
        }

        text = json.dumps(report, indent=2, default=str)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(text)

        return text
