"""Synthesize valid pcap files from protocol grammars."""

from __future__ import annotations

import struct
import random
from pathlib import Path

from .grammar_model import PacketTemplate


PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1
PCAP_LINKTYPE_RAW = 101

ETHERNET_HEADER = bytes(12) + b"\x08\x00"  # dst + src + IPv4 ethertype
IPV4_TEMPLATE = bytearray([
    0x45, 0x00,       # version/IHL, DSCP
    0x00, 0x00,       # total length (filled later)
    0x00, 0x01, 0x00, 0x00,  # ID, flags/offset
    0x40, 0x00,       # TTL=64, protocol (filled later)
    0x00, 0x00,       # checksum
    0x0a, 0x00, 0x00, 0x01,  # src IP
    0x0a, 0x00, 0x00, 0x02,  # dst IP
])

PROTO_UDP = 17
PROTO_TCP = 6


class PcapSynthesizer:
    """Generate pcap files containing protocol-conformant packets."""

    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)

    def synthesize(self, template: PacketTemplate, count: int = 1,
                   transport: str = "udp", src_port: int = 12345,
                   dst_port: int = 80) -> bytes:
        """Generate a complete pcap file with `count` packets from the template."""
        pcap = self._pcap_header()

        for _ in range(count):
            payload = template.generate(self.rng)
            packet = self._wrap_packet(payload, transport, src_port, dst_port)
            pcap += self._packet_record(packet)

        return bytes(pcap)

    def synthesize_mutated(self, template: PacketTemplate, count: int = 10,
                           mutation_rate: float = 0.15,
                           transport: str = "udp", src_port: int = 12345,
                           dst_port: int = 80) -> list[bytes]:
        """Generate multiple pcaps, each with a mutated packet."""
        pcaps = []
        for _ in range(count):
            payload = template.generate_mutated(self.rng, mutation_rate)
            packet = self._wrap_packet(payload, transport, src_port, dst_port)
            pcap = self._pcap_header() + self._packet_record(packet)
            pcaps.append(bytes(pcap))
        return pcaps

    def write_pcap(self, data: bytes, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _pcap_header(self) -> bytearray:
        return bytearray(struct.pack("<IHHiIII",
            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_ETHERNET,
        ))

    def _packet_record(self, packet_data: bytes) -> bytearray:
        ts_sec = self.rng.randint(1600000000, 1700000000)
        ts_usec = self.rng.randint(0, 999999)
        caplen = len(packet_data)
        return bytearray(struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen)) + bytearray(packet_data)

    def _wrap_packet(self, payload: bytes, transport: str,
                     src_port: int, dst_port: int) -> bytes:
        if transport == "udp":
            transport_hdr = self._udp_header(src_port, dst_port, len(payload))
            proto = PROTO_UDP
        else:
            transport_hdr = self._tcp_header(src_port, dst_port)
            proto = PROTO_TCP

        ip = bytearray(IPV4_TEMPLATE)
        total_len = 20 + len(transport_hdr) + len(payload)
        struct.pack_into(">H", ip, 2, total_len)
        ip[9] = proto
        checksum = self._ip_checksum(ip)
        struct.pack_into(">H", ip, 10, checksum)

        return ETHERNET_HEADER + bytes(ip) + transport_hdr + payload

    def _udp_header(self, src_port: int, dst_port: int, payload_len: int) -> bytes:
        udp_len = 8 + payload_len
        return struct.pack(">HHHH", src_port, dst_port, udp_len, 0)

    def _tcp_header(self, src_port: int, dst_port: int) -> bytes:
        return struct.pack(">HHIIBBHHH",
            src_port, dst_port,
            self.rng.randint(0, 0xFFFFFFFF),  # seq
            0,  # ack
            0x50, 0x02,  # data offset=5, SYN
            65535,  # window
            0, 0,   # checksum, urgent
        )

    @staticmethod
    def _ip_checksum(header: bytearray) -> int:
        if len(header) % 2:
            header = header + bytearray(1)
        total = 0
        for i in range(0, len(header), 2):
            total += (header[i] << 8) + header[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF
