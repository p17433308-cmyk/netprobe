"""Containerized execution harness via Docker."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .base import BaseHarness, ExecutionResult
from .sanitizer_parser import parse_sanitizer_output


class DockerHarness(BaseHarness):
    """Run targets inside Docker containers for isolation."""

    def __init__(self, image: str, tool_cmd: list[str],
                 timeout: float = 15.0, memory_limit_mb: int = 2048):
        super().__init__(timeout=timeout, memory_limit_mb=memory_limit_mb)
        self.image = image
        self.tool_cmd = tool_cmd

    def find_binary(self) -> Path:
        return Path("/usr/bin/docker")

    def get_version(self) -> str:
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", self.image] + self.tool_cmd[:1] + ["--version"],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return f"docker:{self.image}"

    def execute(self, pcap_path: Path, **kwargs) -> ExecutionResult:
        cmd = [
            "docker", "run", "--rm",
            f"--memory={self.memory_limit_mb}m",
            "-v", f"{pcap_path.parent}:/data:ro",
            self.image,
        ] + self.tool_cmd + [f"/data/{pcap_path.name}"]

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout)
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
