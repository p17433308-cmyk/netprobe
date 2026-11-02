"""Registry of supported target tools and their configurations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class TargetInfo:
    name: str
    language: str
    parser_glob: str
    harness_type: str
    decode_as_support: bool = False
    description: str = ""


BUILTIN_TARGETS: dict[str, TargetInfo] = {
    "wireshark": TargetInfo(
        name="wireshark",
        language="c",
        parser_glob="epan/dissectors/packet-*.c",
        harness_type="tshark",
        decode_as_support=True,
        description="Wireshark/tshark — 3000+ C protocol dissectors",
    ),
    "suricata": TargetInfo(
        name="suricata",
        language="rust",
        parser_glob="rust/src/**/*.rs",
        harness_type="suricata",
        description="Suricata IDS — Rust+C protocol parsers",
    ),
    "tcpdump": TargetInfo(
        name="tcpdump",
        language="c",
        parser_glob="print-*.c",
        harness_type="tcpdump",
        description="tcpdump — C protocol print functions",
    ),
    "zeek": TargetInfo(
        name="zeek",
        language="cpp",
        parser_glob="src/analyzer/**/*.cc",
        harness_type="zeek",
        description="Zeek — C++ protocol analyzers",
    ),
    "snort": TargetInfo(
        name="snort",
        language="cpp",
        parser_glob="src/service_inspectors/**/*.cc",
        harness_type="snort",
        description="Snort 3 — C++ service inspectors",
    ),
}


def get_target(name: str) -> TargetInfo:
    target = BUILTIN_TARGETS.get(name.lower())
    if not target:
        available = ", ".join(BUILTIN_TARGETS.keys())
        raise ValueError(f"Unknown target '{name}'. Available: {available}")
    return target


def list_targets() -> list[TargetInfo]:
    return list(BUILTIN_TARGETS.values())
