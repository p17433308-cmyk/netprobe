"""Parse AddressSanitizer / UBSan / MSan output from crashes."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SanitizerReport:
    sanitizer: str  # "asan", "ubsan", "msan"
    error_type: str  # "heap-buffer-overflow", "stack-buffer-overflow", etc.
    access_type: str | None = None  # "READ", "WRITE"
    access_size: int | None = None
    crash_address: str | None = None
    alloc_size: int | None = None
    stack_frames: list[str] | None = None
    source_file: str | None = None
    source_line: int | None = None
    function_name: str | None = None


ASAN_ERROR_RE = re.compile(
    r'==\d+==ERROR:\s+AddressSanitizer:\s+([\w-]+)\s+on\s+address\s+(0x[\da-f]+)\s+'
    r'at pc\s+(0x[\da-f]+)',
    re.IGNORECASE,
)
ASAN_ACCESS_RE = re.compile(
    r'(READ|WRITE)\s+of\s+size\s+(\d+)',
    re.IGNORECASE,
)
ASAN_ALLOC_RE = re.compile(
    r'allocated\s+by\s+thread.*?of\s+size\s+(\d+)',
    re.IGNORECASE | re.DOTALL,
)
ASAN_FRAME_RE = re.compile(
    r'#(\d+)\s+(0x[\da-f]+)\s+in\s+(\S+)\s+(\S+):(\d+)',
)
UBSAN_ERROR_RE = re.compile(
    r'([\w/.]+):(\d+):\d+:\s+runtime\s+error:\s+(.+)',
)
SIGNAL_RE = re.compile(
    r'==\d+==.*?signal\s+(\d+)\s+\((\w+)\)',
    re.IGNORECASE,
)


def parse_sanitizer_output(stderr: str) -> SanitizerReport | None:
    """Parse ASAN/UBSAN/MSAN output and extract structured crash info."""

    asan_match = ASAN_ERROR_RE.search(stderr)
    if asan_match:
        report = SanitizerReport(
            sanitizer="asan",
            error_type=asan_match.group(1),
            crash_address=asan_match.group(2),
        )

        access = ASAN_ACCESS_RE.search(stderr)
        if access:
            report.access_type = access.group(1)
            report.access_size = int(access.group(2))

        alloc = ASAN_ALLOC_RE.search(stderr)
        if alloc:
            report.alloc_size = int(alloc.group(1))

        frames = []
        for fm in ASAN_FRAME_RE.finditer(stderr):
            func = fm.group(3)
            src = fm.group(4)
            line = fm.group(5)
            frames.append(f"{func} ({src}:{line})")
            if not report.function_name:
                report.function_name = func
                report.source_file = src
                report.source_line = int(line)

        report.stack_frames = frames
        return report

    ubsan_match = UBSAN_ERROR_RE.search(stderr)
    if ubsan_match:
        return SanitizerReport(
            sanitizer="ubsan",
            error_type=ubsan_match.group(3).strip(),
            source_file=ubsan_match.group(1),
            source_line=int(ubsan_match.group(2)),
        )

    if "MemorySanitizer" in stderr:
        return SanitizerReport(
            sanitizer="msan",
            error_type="use-of-uninitialized-value",
        )

    return None
