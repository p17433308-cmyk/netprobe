"""Delta-debugging pcap minimizer — find the smallest input that still triggers the crash."""

from __future__ import annotations

import shutil
from pathlib import Path

from netprobe.harness.base import BaseHarness, ExecutionResult


class DeltaDebugMinimizer:
    """Minimize a crash-triggering pcap via delta debugging."""

    def __init__(self, harness: BaseHarness, max_iterations: int = 200):
        self.harness = harness
        self.max_iterations = max_iterations

    def minimize(self, crash_pcap: Path) -> Path:
        data = crash_pcap.read_bytes()
        if not self._triggers_crash(data):
            return crash_pcap

        minimized = self._ddmin(data)

        out_path = crash_pcap.parent / f"{crash_pcap.stem}_min{crash_pcap.suffix}"
        out_path.write_bytes(minimized)
        return out_path

    def _ddmin(self, data: bytes) -> bytes:
        n = 2
        iteration = 0

        while len(data) >= 2 and iteration < self.max_iterations:
            chunk_size = max(len(data) // n, 1)
            reduced = False

            for i in range(n):
                start = i * chunk_size
                end = min(start + chunk_size, len(data))
                candidate = data[:start] + data[end:]

                if len(candidate) > 0 and self._triggers_crash(candidate):
                    data = candidate
                    n = max(n - 1, 2)
                    reduced = True
                    break

                iteration += 1
                if iteration >= self.max_iterations:
                    break

            if not reduced:
                if n >= len(data):
                    break
                n = min(n * 2, len(data))

            iteration += 1

        return data

    def _triggers_crash(self, data: bytes) -> bool:
        tmp = Path("/tmp/netprobe_minimize_tmp.pcap")
        tmp.write_bytes(data)
        try:
            result = self.harness.execute(tmp)
            return result.crashed
        finally:
            tmp.unlink(missing_ok=True)
