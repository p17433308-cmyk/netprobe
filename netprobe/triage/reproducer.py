"""Generate standalone crash reproduction scripts."""

from __future__ import annotations

from pathlib import Path


class ReproducerGenerator:
    """Generate reproduction scripts and Docker one-liners for crashes."""

    def generate_script(self, crash_dir: Path, tool: str = "wireshark",
                        decode_as: str | None = None) -> str:
        pcap_files = list(crash_dir.glob("*.pcap")) + list(crash_dir.glob("*.pcapng"))
        pcap = pcap_files[0].name if pcap_files else "crash.pcap"

        tool_cmds = {
            "wireshark": self._tshark_cmd(pcap, decode_as),
            "tcpdump": f'tcpdump -r "$PCAP" -nn -vv --print 2>&1',
            "suricata": f'suricata -r "$PCAP" -l /tmp/suricata_repro 2>&1',
            "zeek": f'zeek -r "$PCAP" -C 2>&1',
            "snort": f'snort -r "$PCAP" -l /tmp/snort_repro -q 2>&1',
        }
        cmd = tool_cmds.get(tool, tool_cmds["wireshark"])

        return f"""#!/bin/bash
# NetProbe Crash Reproducer
# Tool: {tool}
# Generated from: {crash_dir}

set -e

PCAP="${{1:-{pcap}}}"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:print_scariness=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

echo "[*] Reproducing crash with {tool}..."
echo "[*] PCAP: $PCAP"
echo ""

{cmd}

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[!] CRASH CONFIRMED — exit code $EXIT_CODE"
else
    echo ""
    echo "[+] No crash — tool exited normally"
fi

exit $EXIT_CODE
"""

    def generate_docker_oneliner(self, pcap_name: str, tool: str = "wireshark",
                                  image: str | None = None) -> str:
        img = image or f"netprobe/{tool}-asan:latest"
        return (
            f"docker run --rm -v $(pwd):/data {img} "
            f"/bin/bash -c 'export ASAN_OPTIONS=\"detect_leaks=0:abort_on_error=1\"; "
            f"{self._docker_tool_cmd(tool, pcap_name)}'"
        )

    def write_reproducer(self, crash_dir: Path, tool: str = "wireshark",
                         decode_as: str | None = None) -> Path:
        script = self.generate_script(crash_dir, tool, decode_as)
        out = crash_dir / "reproduce.sh"
        out.write_text(script)
        out.chmod(0o755)
        return out

    def _tshark_cmd(self, pcap: str, decode_as: str | None) -> str:
        base = f'tshark -r "$PCAP" -V'
        if decode_as:
            base += f" --decode-as {decode_as}"
        return base + " 2>&1"

    def _docker_tool_cmd(self, tool: str, pcap: str) -> str:
        cmds = {
            "wireshark": f"tshark -r /data/{pcap} -V",
            "tcpdump": f"tcpdump -r /data/{pcap} -nn -vv --print",
            "suricata": f"suricata -r /data/{pcap} -l /tmp/out",
            "zeek": f"zeek -r /data/{pcap} -C",
            "snort": f"snort -r /data/{pcap} -l /tmp/out -q",
        }
        return cmds.get(tool, cmds["wireshark"])
