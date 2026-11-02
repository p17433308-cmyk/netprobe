"""Map crashes to source lines via ASAN symbolization."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SourceLocation:
    function: str
    file_path: str | None
    line_number: int | None
    column: int | None


@dataclass
class RootCauseMapping:
    crash_type: str
    access_type: str | None
    access_size: int | None
    faulting_location: SourceLocation
    allocation_location: SourceLocation | None
    stack_depth: int
    frames: list[SourceLocation]


class RootCauseAnalyzer:
    """Parse ASAN reports to map crashes to exact source locations."""

    def analyze(self, asan_report: str) -> RootCauseMapping | None:
        if not asan_report or "ERROR:" not in asan_report:
            return None

        crash_type = self._extract_crash_type(asan_report)
        access_type, access_size = self._extract_access_info(asan_report)
        frames = self._extract_stack_frames(asan_report)
        alloc_frames = self._extract_alloc_frames(asan_report)

        if not frames:
            return None

        return RootCauseMapping(
            crash_type=crash_type,
            access_type=access_type,
            access_size=access_size,
            faulting_location=frames[0],
            allocation_location=alloc_frames[0] if alloc_frames else None,
            stack_depth=len(frames),
            frames=frames,
        )

    def _extract_crash_type(self, report: str) -> str:
        match = re.search(r"ERROR:\s*\w+:\s*(\S+)", report)
        return match.group(1) if match else "unknown"

    def _extract_access_info(self, report: str) -> tuple[str | None, int | None]:
        match = re.search(r"(READ|WRITE)\s+of\s+size\s+(\d+)", report)
        if match:
            return match.group(1), int(match.group(2))
        return None, None

    def _extract_stack_frames(self, report: str) -> list[SourceLocation]:
        frames = []
        for match in re.finditer(
            r"#\d+\s+\S+\s+in\s+(\w+)\s+(\S+):(\d+)(?::(\d+))?", report
        ):
            frames.append(SourceLocation(
                function=match.group(1),
                file_path=match.group(2),
                line_number=int(match.group(3)),
                column=int(match.group(4)) if match.group(4) else None,
            ))

        if not frames:
            for match in re.finditer(r"#\d+\s+\S+\s+in\s+(\w+)", report):
                frames.append(SourceLocation(
                    function=match.group(1),
                    file_path=None,
                    line_number=None,
                    column=None,
                ))

        return frames

    def _extract_alloc_frames(self, report: str) -> list[SourceLocation]:
        alloc_section = re.search(
            r"(?:allocated|freed) by thread.*?(?=\n\n|\Z)", report, re.DOTALL
        )
        if not alloc_section:
            return []
        return self._extract_stack_frames(alloc_section.group(0))
