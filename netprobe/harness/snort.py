"""Snort 3 execution harness."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .base import BaseHarness, ExecutionResult
from .sanitizer_parser import parse_sanitizer_output


class SnortHarness(BaseHarness):

    def __init__(self, binary_path: Path | None = None, timeout: float = 15.0,
                 memory_limit_mb: int = 2048):
        super().__init__(binary_path, timeout, memory_limit_mb)
        if not self.binary_path:
            self.binary_path = self.find_binary()

    def find_binary(self) -> Path:
        for name in ["snort", "snort3"]:
            path = shutil.which(name)
            if path:
                return Path(path)
        raise FileNotFoundError("snort not found. Install Snort 3 or set --binary path.")

    def get_version(self) -> str:
        try:
            result = subprocess.run(
                [str(self.binary_path), "-V"],
                capture_output=True, text=True, timeout=5,
            )
            return (result.stdout or result.stderr).strip().split("\n")[0]
        except Exception:
            return "unknown"

    def execute(self, pcap_path: Path, **kwargs) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="netprobe_snort_") as logdir:
            cmd = [str(self.binary_path), "-r", str(pcap_path),
                   "-l", logdir, "-q", "--pcap-show"]

            env = {
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
            }

            start = time.monotonic()
            timed_out = False
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.timeout, env=env)
                return_code = proc.returncode
                stdout = proc.stdout
                stderr = proc.stderr
            except subprocess.TimeoutExpired as e:
                timed_out = True
                return_code = -1
                stdout = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")

            duration = time.monotonic() - start
            crashed = return_code != 0 and not timed_out

            asan_report = crash_type = crash_function = crash_address = None
            stack_trace = None

            if crashed or "ERROR: AddressSanitizer" in stderr:
                crashed = True
                san = parse_sanitizer_output(stderr)
                if san:
                    asan_report = stderr
                    crash_type = san.error_type
                    crash_function = san.function_name
                    crash_address = san.crash_address
                    stack_trace = san.stack_frames

            return ExecutionResult(
                pcap_path=pcap_path, return_code=return_code,
                stdout=stdout[:5000], stderr=stderr[:10000],
                duration=duration, timed_out=timed_out, crashed=crashed,
                asan_report=asan_report, crash_type=crash_type,
                crash_function=crash_function, crash_address=crash_address,
                stack_trace=stack_trace,
            )
