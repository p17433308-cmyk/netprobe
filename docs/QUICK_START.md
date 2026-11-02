# Quick Start — NetProbe

## Install

```bash
cd netprobe
pip install -e .
```

## 1. Reconnaissance — Find High-Risk Parsers

```bash
netprobe recon --source /path/to/wireshark --target wireshark --top 30
```

This maps all 3000+ dissectors, scores complexity, identifies OSS-Fuzz coverage gaps, and ranks them by exploitability risk.

## 2. Static Audit — Find Dangerous Code Patterns

```bash
netprobe audit --source /path/to/wireshark --target wireshark
```

Scans for unchecked memcpy, integer overflow in allocations, unbounded loops, recursive dissector calls, format string risks, and more.

## 3. Grammar Extraction + Pcap Generation

```bash
netprobe grammar --source /path/to/wireshark --protocol dns --count 100
```

Extracts protocol field definitions from dissector source code and generates structurally valid mutated pcaps.

## 4. Fuzz — Find Crashes

```bash
netprobe fuzz --target wireshark --binary /path/to/tshark --protocol dns --duration 3600
```

Runs mutation-based fuzzing with bitflip, overflow, magic value, and structure-aware strategies. Crashes are automatically saved and deduplicated.

## 5. Differential Testing

```bash
netprobe diff --pcap-dir corpus/seeds
```

Runs pcaps through tshark, tcpdump, and suricata. Flags when one tool crashes and others don't.

## 6. Triage — Classify Crashes

```bash
netprobe triage --crash-dir corpus/crashes --binary /path/to/tshark
```

Replays crashes, deduplicates by stack hash, classifies CWE, estimates CVSS, flags RCE potential.

## 7. Generate CVE Report

```bash
netprobe report --crash-id <CRASH_ID> --crash-dir corpus/crashes
```

## 8. Weaponize — Package PoC

```bash
netprobe weaponize --pcap corpus/crashes/crash_001.pcap --binary /path/to/tshark
```

Minimizes the crash pcap, verifies stability, and packages into a disclosure-ready bundle with reproduction script and Dockerfile.

## 9. Honeypot Traffic

```bash
netprobe honeypot --profile enterprise --packets 5000 --output honeypot.pcap
```

## 10. AI Analysis

```bash
export ANTHROPIC_API_KEY=sk-...
netprobe ai --source /path/to/wireshark/epan/dissectors/packet-dns.c
```

## 11. Dashboard

```bash
netprobe dashboard --results campaign_report.json --output dashboard.html
```

## 12. Live Demo

```bash
netprobe demo --target wireshark --binary /path/to/tshark
```
