"""Detect and catalog crashes from fuzzing runs."""

from __future__ import annotations

import hashlib
from pathlib import Path

from netprobe.harness.wireshark import WiresharkHarness
from netprobe.harness.sanitizer_parser import parse_sanitizer_output


class CrashDetector:
    def __init__(self, binary_path: Path | None = None, timeout: float = 10.0):
        self.harness = WiresharkHarness(binary_path=binary_path, timeout=timeout)

    def replay(self, pcap_path: Path) -> dict | None:
        """Replay a pcap and determine if it causes a crash."""
        result = self.harness.execute(pcap_path)

        if not result.crashed and not result.timed_out:
            return None

        crash_id = self._generate_id(result)

        report = {
            "crash_id": crash_id,
            "filename": pcap_path.name,
            "pcap_path": str(pcap_path),
            "return_code": result.return_code,
            "crashed": result.crashed,
            "timed_out": result.timed_out,
            "duration": result.duration,
            "crash_type": result.crash_type or ("timeout" if result.timed_out else "unknown"),
            "function": result.crash_function,
            "address": result.crash_address,
            "stack_trace": result.stack_trace or [],
            "asan_report": result.asan_report,
            "stderr_snippet": result.stderr[:2000],
        }

        return report

    def _generate_id(self, result) -> str:
        """Generate a unique crash ID based on stack trace."""
        if result.stack_trace:
            key = "|".join(result.stack_trace[:5])
        elif result.crash_function:
            key = f"{result.crash_type}:{result.crash_function}"
        else:
            key = f"{result.crash_type}:{result.return_code}"

        return hashlib.sha256(key.encode()).hexdigest()[:16]
