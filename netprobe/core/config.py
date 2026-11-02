"""Campaign and tool configuration."""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TargetConfig:
    name: str
    language: str
    source_path: Path | None = None
    binary_path: Path | None = None
    parser_glob: str = ""
    build_cmd: str = ""
    sanitizer_flags: str = ""
    harness_type: str = ""
    decode_as_support: bool = False

    @classmethod
    def from_yaml(cls, path: Path) -> TargetConfig:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(
            name=data["name"],
            language=data["language"],
            source_path=Path(data["source_path"]) if data.get("source_path") else None,
            binary_path=Path(data["binary_path"]) if data.get("binary_path") else None,
            parser_glob=data.get("parser_glob", ""),
            build_cmd=data.get("build_cmd", ""),
            sanitizer_flags=data.get("sanitizer_flags", ""),
            harness_type=data.get("harness_type", ""),
            decode_as_support=data.get("decode_as_support", False),
        )


@dataclass
class FuzzConfig:
    duration_seconds: int = 3600
    cores: int = 1
    timeout_per_exec: float = 10.0
    memory_limit_mb: int = 2048
    mutators: list[str] = field(default_factory=lambda: ["bitflip", "overflow", "magic"])
    corpus_dir: Path = field(default_factory=lambda: Path("corpus/seeds"))
    crash_dir: Path = field(default_factory=lambda: Path("corpus/crashes"))
    coverage_enabled: bool = False


@dataclass
class CampaignConfig:
    name: str
    target: TargetConfig
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)
    protocols: list[str] = field(default_factory=list)
    output_dir: Path = field(default_factory=lambda: Path("output"))

    @classmethod
    def from_yaml(cls, path: Path) -> CampaignConfig:
        with open(path) as f:
            data = yaml.safe_load(f)
        target = TargetConfig.from_yaml(Path(data["target_config"]))
        fuzz_data = data.get("fuzz", {})
        fuzz = FuzzConfig(
            duration_seconds=fuzz_data.get("duration_seconds", 3600),
            cores=fuzz_data.get("cores", 1),
            timeout_per_exec=fuzz_data.get("timeout_per_exec", 10.0),
            memory_limit_mb=fuzz_data.get("memory_limit_mb", 2048),
            mutators=fuzz_data.get("mutators", ["bitflip", "overflow", "magic"]),
            corpus_dir=Path(fuzz_data.get("corpus_dir", "corpus/seeds")),
            crash_dir=Path(fuzz_data.get("crash_dir", "corpus/crashes")),
            coverage_enabled=fuzz_data.get("coverage_enabled", False),
        )
        return cls(
            name=data["name"],
            target=target,
            fuzz=fuzz,
            protocols=data.get("protocols", []),
            output_dir=Path(data.get("output_dir", "output")),
        )
