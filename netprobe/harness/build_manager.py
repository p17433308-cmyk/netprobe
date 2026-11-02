"""Auto-build targets with sanitizers from source."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BuildConfig:
    source_dir: Path
    build_dir: Path
    sanitizers: list[str]
    extra_flags: list[str]


class BuildManager:
    """Build network security tools from source with sanitizer instrumentation."""

    TOOL_BUILD_CONFIGS = {
        "wireshark": {
            "cmake_flags": [
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DENABLE_ASAN=ON",
                "-DENABLE_UBSAN=ON",
                "-DCMAKE_C_FLAGS=-fprofile-arcs -ftest-coverage",
            ],
            "binary_path": "run/tshark",
        },
        "suricata": {
            "configure_flags": [
                "--enable-debug",
                "CFLAGS=-fsanitize=address -fno-omit-frame-pointer -g",
                "LDFLAGS=-fsanitize=address",
            ],
            "binary_path": "src/suricata",
        },
        "tcpdump": {
            "configure_flags": [
                "CFLAGS=-fsanitize=address -fno-omit-frame-pointer -g",
                "LDFLAGS=-fsanitize=address",
            ],
            "binary_path": "tcpdump",
        },
    }

    def build(self, tool: str, source_dir: Path, build_dir: Path | None = None) -> Path:
        if tool not in self.TOOL_BUILD_CONFIGS:
            raise ValueError(f"No build config for {tool}. Available: {list(self.TOOL_BUILD_CONFIGS)}")

        config = self.TOOL_BUILD_CONFIGS[tool]
        bd = build_dir or source_dir / "build_asan"
        bd.mkdir(parents=True, exist_ok=True)

        if "cmake_flags" in config:
            self._cmake_build(source_dir, bd, config["cmake_flags"])
        elif "configure_flags" in config:
            self._autotools_build(source_dir, bd, config["configure_flags"])

        binary = bd / config["binary_path"]
        if not binary.exists():
            binary = source_dir / config["binary_path"]

        if not binary.exists():
            raise FileNotFoundError(f"Build succeeded but binary not found at {binary}")

        return binary

    def _cmake_build(self, source: Path, build: Path, flags: list[str]):
        subprocess.run(
            ["cmake", str(source)] + flags,
            cwd=build, check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            ["make", "-j4"],
            cwd=build, check=True, capture_output=True, timeout=600,
        )

    def _autotools_build(self, source: Path, build: Path, flags: list[str]):
        configure = source / "configure"
        if not configure.exists():
            subprocess.run(
                ["autoreconf", "-fvi"],
                cwd=source, check=True, capture_output=True, timeout=120,
            )
        subprocess.run(
            [str(configure)] + flags + [f"--prefix={build}/install"],
            cwd=build, check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            ["make", "-j4"],
            cwd=build, check=True, capture_output=True, timeout=600,
        )
