"""Abstract harness interface for target tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecutionResult:
    pcap_path: Path
    return_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool
    crashed: bool
    asan_report: str | None = None
    crash_type: str | None = None
    crash_function: str | None = None
    crash_address: str | None = None
    stack_trace: list[str] | None = None


class BaseHarness(ABC):
    def __init__(self, binary_path: Path | None = None, timeout: float = 10.0,
                 memory_limit_mb: int = 2048):
        self.binary_path = binary_path
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb

    @abstractmethod
    def find_binary(self) -> Path:
        """Auto-detect the target binary."""
        ...

    @abstractmethod
    def execute(self, pcap_path: Path, **kwargs) -> ExecutionResult:
        """Run the target on a pcap and capture the result."""
        ...

    @abstractmethod
    def get_version(self) -> str:
        """Get the target tool version string."""
        ...
