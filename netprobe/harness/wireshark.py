"""Wireshark/tshark execution harness."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .base import BaseHarness, ExecutionResult
from .sanitizer_parser import parse_sanitizer_output


class WiresharkHarness(BaseHarness):
    """Run tshark on pcap files and detect crashes."""

    def __init__(self, binary_path: Path | None = None, timeout: float = 10.0,
                 memory_limit_mb: int = 2048, decode_as: str | None = None):
        super().__init__(binary_path, timeout, memory_limit_mb)
        self.decode_as = decode_as
        if not self.binary_path:
            self.binary_path = self.find_binary()

    def find_binary(self) -> Path:
        for name in ["tshark", "rawshark"]:
            path = shutil.which(name)
            if path:
                return Path(path)
        raise FileNotFoundError(
            "tshark not found. Install Wireshark or set --binary path.\n"
            "For ASAN builds, build from source with:\n"
            "  cmake -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug .."
        )

    def get_version(self) -> str:
        try:
            result = subprocess.run(
                [str(self.binary_path), "--version"],
                capture_output=True, text=True, timeout=5,
            )
            first_line = result.stdout.split("\n")[0]
            return first_line.strip()
        except Exception:
            return "unknown"

    def execute(self, pcap_path: Path, protocol: str | None = None,
                decode_as: str | None = None) -> ExecutionResult:
        cmd = [str(self.binary_path)]

        da = decode_as or self.decode_as
        if da:
            cmd.extend(["-d", da])

        cmd.extend([
            "-r", str(pcap_path),
            "-V",
            "-x",
        ])

        env = {
            "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
            "MSAN_OPTIONS": "print_stats=1",
        }

        import os
        full_env = {**os.environ, **env}

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=full_env,
            )
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
        asan_report = None
        crash_type = None
        crash_function = None
        crash_address = None
        stack_trace = None

        if crashed or "ERROR: AddressSanitizer" in stderr or "runtime error" in stderr:
            crashed = True
            san = parse_sanitizer_output(stderr)
            if san:
                asan_report = stderr
                crash_type = san.error_type
                crash_function = san.function_name
                crash_address = san.crash_address
                stack_trace = san.stack_frames
            elif return_code < 0:
                import signal as sig
                try:
                    signame = sig.Signals(-return_code).name
                    crash_type = f"signal-{signame}"
                except (ValueError, AttributeError):
                    crash_type = f"exit-{return_code}"

        return ExecutionResult(
            pcap_path=pcap_path,
            return_code=return_code,
            stdout=stdout[:5000],
            stderr=stderr[:10000],
            duration=duration,
            timed_out=timed_out,
            crashed=crashed,
            asan_report=asan_report,
            crash_type=crash_type,
            crash_function=crash_function,
            crash_address=crash_address,
            stack_trace=stack_trace,
        )

    def check_asan_build(self) -> bool:
        """Check if the binary was built with AddressSanitizer."""
        try:
            result = subprocess.run(
                ["ldd", str(self.binary_path)],
                capture_output=True, text=True, timeout=5,
            )
            return "libasan" in result.stdout
        except Exception:
            return False
