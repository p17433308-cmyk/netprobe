"""LLM-powered CVE description writer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CVEDescription:
    title: str
    description: str
    impact: str
    affected_versions: str
    reproduction_steps: str
    suggested_fix: str


class ReportWriter:
    """Generate human-readable CVE descriptions from crash data."""

    def generate_description(self, crash_data: dict) -> CVEDescription:
        crash_type = crash_data.get("crash_type", "memory corruption")
        function = crash_data.get("function", "unknown")
        tool = crash_data.get("tool", "network security tool")
        protocol = crash_data.get("protocol", "unknown protocol")
        cwe = crash_data.get("cwe", "CWE-787")
        cvss = crash_data.get("cvss", 7.5)

        if "heap-buffer-overflow" in crash_type.lower() or "heap-overflow" in crash_type.lower():
            vuln_type = "heap-based buffer overflow"
            impact_detail = "arbitrary code execution or denial of service"
        elif "use-after-free" in crash_type.lower():
            vuln_type = "use-after-free"
            impact_detail = "arbitrary code execution, information disclosure, or denial of service"
        elif "stack-buffer-overflow" in crash_type.lower():
            vuln_type = "stack-based buffer overflow"
            impact_detail = "arbitrary code execution or denial of service"
        elif "null" in crash_type.lower():
            vuln_type = "NULL pointer dereference"
            impact_detail = "denial of service"
        else:
            vuln_type = "memory corruption"
            impact_detail = "denial of service or potential code execution"

        title = f"{tool}: {vuln_type} in {protocol} parser ({function})"

        description = (
            f"A {vuln_type} vulnerability exists in the {protocol} protocol parser "
            f"of {tool}, specifically in the {function} function. An attacker can "
            f"craft a malicious {protocol} packet or pcap file that, when processed "
            f"by {tool}, triggers a {vuln_type} condition. This vulnerability is "
            f"classified as {cwe} with a CVSS score of {cvss}."
        )

        impact = (
            f"Processing a specially crafted {protocol} packet can cause {impact_detail}. "
            f"In network monitoring deployments, an attacker can send malicious traffic "
            f"to crash or compromise the monitoring tool, blinding the defender. "
            f"In forensic analysis scenarios, opening a crafted pcap file triggers "
            f"the vulnerability in the analyst's environment."
        )

        reproduction = (
            f"1. Build {tool} with AddressSanitizer (ASAN) enabled\n"
            f"2. Process the attached proof-of-concept pcap file\n"
            f"3. Observe the ASAN report indicating {vuln_type} in {function}"
        )

        fix = (
            f"Add bounds checking in {function} to validate packet field lengths "
            f"before memory operations. Ensure all packet-sourced length and count "
            f"values are validated against available buffer sizes."
        )

        return CVEDescription(
            title=title,
            description=description,
            impact=impact,
            affected_versions=crash_data.get("affected_versions", "Unknown"),
            reproduction_steps=reproduction,
            suggested_fix=fix,
        )
