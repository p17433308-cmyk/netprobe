"""Craft live network packets from crash-triggering pcaps."""

from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass


@dataclass
class CraftedPacket:
    raw_bytes: bytes
    protocol: str
    description: str
    crash_type: str
    target_tool: str


class PacketCrafter:
    """Extract payloads from crash pcaps and prepare them for live injection."""

    def extract_payloads(self, pcap_path: Path) -> list[bytes]:
        """Extract raw packet payloads from a pcap file."""
        data = pcap_path.read_bytes()
        if len(data) < 24:
            return []

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            return []

        linktype = struct.unpack_from(f"{endian}I", data, 20)[0]
        offset = 24
        payloads = []

        while offset + 16 <= len(data):
            caplen = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
            pkt_start = offset + 16
            pkt_end = min(pkt_start + caplen, len(data))

            if pkt_end > pkt_start:
                raw_pkt = data[pkt_start:pkt_end]
                payload = self._strip_headers(raw_pkt, linktype)
                if payload:
                    payloads.append(payload)

            offset = pkt_end

        return payloads

    def _strip_headers(self, packet: bytes, linktype: int) -> bytes | None:
        """Strip link/IP/transport headers to get the application payload."""
        if linktype == 1:  # Ethernet
            if len(packet) < 14:
                return None
            ethertype = struct.unpack_from(">H", packet, 12)[0]
            offset = 14

            if ethertype == 0x8100:  # VLAN
                offset += 4
                if offset + 2 > len(packet):
                    return None
                ethertype = struct.unpack_from(">H", packet, offset - 2)[0]

            if ethertype == 0x0800:  # IPv4
                if offset + 20 > len(packet):
                    return None
                ihl = (packet[offset] & 0x0F) * 4
                ip_offset = offset + ihl
                proto = packet[offset + 9]

                if proto == 6 and ip_offset + 20 <= len(packet):  # TCP
                    data_offset = ((packet[ip_offset + 12] >> 4) * 4)
                    return packet[ip_offset + data_offset:]
                elif proto == 17 and ip_offset + 8 <= len(packet):  # UDP
                    return packet[ip_offset + 8:]
                else:
                    return packet[ip_offset:]
            else:
                return packet[offset:]
        elif linktype == 101:  # Raw IP
            if len(packet) < 20:
                return None
            ihl = (packet[0] & 0x0F) * 4
            return packet[ihl:]
        else:
            return packet

    def craft_from_crash(self, pcap_path: Path, crash_info: dict) -> list[CraftedPacket]:
        """Create CraftedPacket objects from a crash pcap with metadata."""
        payloads = self.extract_payloads(pcap_path)
        crafted = []
        for payload in payloads:
            crafted.append(CraftedPacket(
                raw_bytes=payload,
                protocol=crash_info.get("protocol", "unknown"),
                description=f"Trigger for {crash_info.get('cwe', 'unknown')} in "
                           f"{crash_info.get('function', 'unknown')}",
                crash_type=crash_info.get("crash_type", "unknown"),
                target_tool=crash_info.get("target_tool", "wireshark"),
            ))
        return crafted
