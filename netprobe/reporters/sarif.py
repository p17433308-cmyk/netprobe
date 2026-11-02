"""SARIF output for GitHub code scanning integration."""

from __future__ import annotations

import json
from pathlib import Path


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


class SarifReporter:
    """Generate SARIF reports from audit findings and crash data."""

    def __init__(self, tool_name: str = "NetProbe", tool_version: str = "1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, findings: list[dict], output_path: Path | None = None) -> dict:
        rules = []
        results = []
        rule_ids = set()

        for i, f in enumerate(findings):
            rule_id = f.get("pattern_name", f.get("cwe", f"finding-{i}"))
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": rule_id.replace("-", " ").title(),
                    "shortDescription": {"text": f.get("detail", rule_id)},
                    "defaultConfiguration": {
                        "level": self._severity_to_level(f.get("severity_score", 5)),
                    },
                    "properties": {
                        "tags": ["security", f.get("cwe", "CWE-unknown")],
                    },
                })

            result = {
                "ruleId": rule_id,
                "level": self._severity_to_level(f.get("severity_score", 5)),
                "message": {"text": f.get("detail", "Potential vulnerability detected")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("file", f.get("parser", "unknown")),
                        },
                        "region": {
                            "startLine": f.get("line", 1),
                        },
                    },
                }],
            }

            if f.get("cwe"):
                result["taxa"] = [{"id": f["cwe"], "toolComponent": {"name": "CWE"}}]

            results.append(result)

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/netprobe/netprobe",
                        "rules": rules,
                    },
                },
                "results": results,
            }],
        }

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(sarif, indent=2))

        return sarif

    def _severity_to_level(self, score: float) -> str:
        if score >= 8:
            return "error"
        if score >= 5:
            return "warning"
        return "note"
