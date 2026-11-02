"""Validate generated packets against Wireshark decode."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValidationResult:
    valid: bool
    protocol_detected: str | None
    fields_decoded: int
    errors: list[str]
    expert_info: list[str]


class PacketValidator:
    """Validate pcaps by running tshark and checking decode output."""

    def __init__(self, tshark_path: str | None = None):
        self.tshark = tshark_path or shutil.which("tshark") or "tshark"

    def validate(self, pcap_data: bytes, expected_protocol: str | None = None,
                 decode_as: str | None = None) -> ValidationResult:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_data)
            pcap_path = f.name

        try:
            cmd = [self.tshark, "-r", pcap_path, "-T", "json", "-V"]
            if decode_as:
                cmd.extend(["--decode-as", decode_as])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return ValidationResult(
                    valid=False, protocol_detected=None,
                    fields_decoded=0, errors=[result.stderr[:500]],
                    expert_info=[],
                )

            try:
                packets = json.loads(result.stdout)
            except json.JSONDecodeError:
                return ValidationResult(
                    valid=False, protocol_detected=None,
                    fields_decoded=0, errors=["Failed to parse tshark JSON output"],
                    expert_info=[],
                )

            if not packets:
                return ValidationResult(
                    valid=False, protocol_detected=None,
                    fields_decoded=0, errors=["No packets decoded"],
                    expert_info=[],
                )

            pkt = packets[0]
            layers = pkt.get("_source", {}).get("layers", {})
            protocol = list(layers.keys())[-1] if layers else None
            field_count = sum(len(v) if isinstance(v, dict) else 1 for v in layers.values())

            expert = []
            for layer_data in layers.values():
                if isinstance(layer_data, dict):
                    for k, v in layer_data.items():
                        if "expert" in k.lower() or "malformed" in str(v).lower():
                            expert.append(f"{k}: {v}")

            valid = True
            errors = []
            if expected_protocol and protocol and expected_protocol.lower() not in protocol.lower():
                errors.append(f"Expected {expected_protocol}, got {protocol}")
                valid = False

            return ValidationResult(
                valid=valid, protocol_detected=protocol,
                fields_decoded=field_count, errors=errors,
                expert_info=expert,
            )
        finally:
            Path(pcap_path).unlink(missing_ok=True)
