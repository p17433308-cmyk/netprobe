#!/usr/bin/env python3 -I
"""ASAN CVE hunt — fuzz tshark-asan Docker image against high-risk dissectors."""

import subprocess, struct, random, time, hashlib, json, sys, os
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from netprobe.mutators.engine import MutationEngine
from netprobe.mutators.nesting import NestingMutator
from netprobe.mutators.encoding import EncodingMutator
from netprobe.mutators.format_string import FormatStringMutator
from netprobe.mutators.ai_guided import AIGuidedMutator
from netprobe.mutators.cross_protocol import CrossProtocolMutator

IMAGE = "netprobe/tshark-asan:4.6.9"
CRASH_DIR = PROJECT / "corpus" / "crashes"
SEED_DIR = PROJECT / "corpus" / "seeds"
TMP = "/tmp/netprobe_asan_fuzz"

CRASH_DIR.mkdir(parents=True, exist_ok=True)
os.makedirs(TMP, exist_ok=True)

# High-risk dissectors from static audit (sorted by weighted severity)
TARGETS = [
    # (decode-as spec, seed protocol, description)
    ("udp.port==5000,cigi", "coap", "CIGI — 7852 dangerous patterns"),
    ("tcp.port==9100,ndps", "http", "NDPS — complex TLV parsing"),
    ("tcp.port==102,s7comm", "modbus", "S7comm — ICS protocol, deep nesting"),
    ("tcp.port==5672,amqp", "mqtt", "AMQP — complex framing"),
    ("tcp.port==3240,dof", "coap", "DOF — IoT protocol"),
    ("tcp.port==80,wcp", "http", "WCP — compression protocol"),
    ("tcp.port==88,spnego", "dns", "SPNEGO — ASN.1 heavy"),
    ("tcp.port==683,giop", "http", "GIOP/CORBA — complex IDL"),
    ("udp.port==53,dns", "dns", "DNS — compression pointers, recursion"),
    ("tcp.port==443,tls", "tls", "TLS — handshake state machine"),
    ("tcp.port==445,smb2", "smb2", "SMB2 — compound requests"),
    ("tcp.port==135,dcerpc", "http", "DCE/RPC — fragmentation"),
    ("udp.port==3868,diameter", "diameter", "Diameter — AVP nesting"),
    ("udp.port==2152,gtp", "coap", "GTPv2 — telecom, IE parsing"),
    ("tcp.port==179,bgp", "bgp", "BGP — path attributes"),
    ("tcp.port==502,modbus", "modbus", "Modbus — ICS"),
    ("udp.port==5353,mdns", "dns", "mDNS — multicast DNS"),
    ("tcp.port==1883,mqtt", "mqtt", "MQTT — topic/payload"),
    ("udp.port==5683,coap", "coap", "CoAP — IoT options"),
    ("tcp.port==80,http", "http", "HTTP — chunked encoding"),
]

SEED_MAP = {}
for f in SEED_DIR.glob("*.pcap"):
    key = f.stem.split("_")[0]
    SEED_MAP.setdefault(key, []).append(f)

engine = MutationEngine()
advanced_mutators = [
    NestingMutator(),
    EncodingMutator(),
    FormatStringMutator(),
    CrossProtocolMutator(),
    AIGuidedMutator(),
]
rng = random.Random(42)

stats = {"tested": 0, "crashes": 0, "unique": 0, "targets_done": 0}
crash_hashes = set()
all_crashes = []

DURATION = int(os.environ.get("HUNT_DURATION", "600"))
PER_TARGET = max(DURATION // len(TARGETS), 15)

print(f"[ASAN HUNT] {len(TARGETS)} targets | {PER_TARGET}s each | {DURATION}s total")
print(f"[ASAN HUNT] Image: {IMAGE}")
print()

hunt_start = time.monotonic()

for tidx, (decode_as, seed_proto, desc) in enumerate(TARGETS):
    if time.monotonic() - hunt_start > DURATION:
        break

    seeds = SEED_MAP.get(seed_proto, list(SEED_DIR.glob("*.pcap"))[:3])
    if not seeds:
        print(f"[SKIP] {desc} — no seeds")
        continue

    print(f"[TARGET {tidx+1}/{len(TARGETS)}] {desc}")
    target_start = time.monotonic()
    target_end = target_start + PER_TARGET
    target_execs = 0
    target_crashes = 0

    while time.monotonic() < target_end:
        seed = rng.choice(seeds)
        data = seed.read_bytes()
        if len(data) < 41:
            continue
        hdr = data[:24]
        pkt_data = data[40:]

        # Generate mutations with all mutator types
        mutations = engine.mutate(pkt_data, count=5)
        adv = rng.choice(advanced_mutators)
        try:
            mutations.extend(adv.mutate(pkt_data, count=3, rng=rng))
        except TypeError:
            mutations.extend(adv.mutate(pkt_data, count=3))

        for m in mutations:
            if time.monotonic() >= target_end:
                break

            # Build pcap
            pcap = hdr + struct.pack("<IIII", 0, 0, len(m), len(m)) + m
            pcap_path = f"{TMP}/fuzz_{tidx}.pcap"
            Path(pcap_path).write_bytes(pcap)

            try:
                r = subprocess.run(
                    [
                        "docker", "run", "--rm",
                        "--memory=512m", "--cpus=1",
                        "-v", f"{TMP}:/data:ro",
                        IMAGE,
                        "-r", f"/data/fuzz_{tidx}.pcap",
                        "-V", "--decode-as", decode_as,
                    ],
                    capture_output=True,
                    timeout=15,
                )
                stats["tested"] += 1
                target_execs += 1
                stderr = r.stderr.decode(errors="replace")

                is_crash = r.returncode != 0 and r.returncode != 2
                is_asan = "ERROR: AddressSanitizer" in stderr or "ERROR: UndefinedBehaviorSanitizer" in stderr
                is_signal = r.returncode < 0

                if is_asan or is_signal or (is_crash and "sanitizer" in stderr.lower()):
                    h = hashlib.md5(pcap).hexdigest()[:12]
                    if h not in crash_hashes:
                        crash_hashes.add(h)
                        stats["crashes"] += 1
                        stats["unique"] += 1
                        target_crashes += 1

                        crash_name = f"asan_{decode_as.split(',')[1]}_{h}"
                        (CRASH_DIR / f"{crash_name}.pcap").write_bytes(pcap)
                        (CRASH_DIR / f"{crash_name}.stderr").write_text(stderr[:5000])

                        # Extract crash type
                        crash_type = "unknown"
                        for ct in ["heap-buffer-overflow", "stack-buffer-overflow",
                                   "use-after-free", "null-dereference",
                                   "heap-use-after-free", "stack-overflow",
                                   "integer-overflow", "signed-integer-overflow"]:
                            if ct in stderr:
                                crash_type = ct
                                break

                        # Extract crashing function
                        func = "unknown"
                        for line in stderr.split("\n"):
                            if "#0" in line and " in " in line:
                                func = line.split(" in ")[1].split(" ")[0] if " in " in line else "unknown"
                                break

                        crash_info = {
                            "id": crash_name,
                            "type": crash_type,
                            "function": func,
                            "dissector": decode_as,
                            "return_code": r.returncode,
                            "pcap": str(CRASH_DIR / f"{crash_name}.pcap"),
                            "stderr_file": str(CRASH_DIR / f"{crash_name}.stderr"),
                        }
                        all_crashes.append(crash_info)

                        print(f"  [CRASH #{stats['crashes']}] {crash_type} in {func}")
                        print(f"    Dissector: {decode_as}")
                        print(f"    Saved: {crash_name}.pcap")
                        if is_asan:
                            # Print first few ASAN lines
                            for sl in stderr.split("\n"):
                                if "ERROR:" in sl or "#0" in sl or "#1" in sl:
                                    print(f"    {sl.strip()}")
                        print()

            except subprocess.TimeoutExpired:
                stats["tested"] += 1
                target_execs += 1

    elapsed = time.monotonic() - target_start
    stats["targets_done"] += 1
    rate = target_execs / max(elapsed, 0.01)
    print(f"  Done: {target_execs} execs ({rate:.0f}/s) | {target_crashes} crashes")
    print()

# Summary
total_elapsed = time.monotonic() - hunt_start
print("=" * 60)
print(f"[HUNT COMPLETE] {total_elapsed:.0f}s")
print(f"  Targets tested: {stats['targets_done']}/{len(TARGETS)}")
print(f"  Total executions: {stats['tested']}")
print(f"  Total crashes: {stats['crashes']}")
print(f"  Unique crashes: {stats['unique']}")
print(f"  Exec rate: {stats['tested']/max(total_elapsed,0.01):.0f}/s")
print("=" * 60)

if all_crashes:
    report = CRASH_DIR / "asan_hunt_report.json"
    report.write_text(json.dumps(all_crashes, indent=2))
    print(f"\nCrash report: {report}")
    print("\nCrash summary:")
    for c in all_crashes:
        print(f"  - {c['type']} in {c['function']} ({c['dissector']})")
else:
    print("\nNo crashes found. Next steps:")
    print("  1. Try longer duration (HUNT_DURATION=3600)")
    print("  2. Add more seed variety")
    print("  3. Try coverage-guided feedback loop")
