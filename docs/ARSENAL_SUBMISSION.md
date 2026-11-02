# NetProbe — Who Watches the Watchmen?

## Tool Summary

NetProbe is an automated vulnerability discovery framework targeting the protocol parsers of network security tools — Wireshark, Suricata, tcpdump, Zeek, and Snort. It combines static code audit, grammar-aware protocol mutation, coverage-guided fuzzing, AI-powered analysis, and differential testing to find real, exploitable bugs in the tools that defenders rely on every day.

## Detailed Description

Every SOC analyst, forensic examiner, and incident responder trusts their tools implicitly. Wireshark parses every packet. Suricata inspects every flow. An attacker who can crash or exploit these tools can blind the entire defense — the IDS crashes silently, the analyst's Wireshark session dies on a crafted pcap, the forensic examination fails at the evidence review stage.

NetProbe systematizes the discovery of these vulnerabilities at scale:

**Reconnaissance Engine** — Maps 3000+ Wireshark dissectors, scores code complexity, identifies dangerous API usage patterns (unchecked tvb_memcpy, integer overflow in wmem_alloc, unguarded recursive calls), and cross-references with OSS-Fuzz to find the gaps — port-dependent dissectors that existing fuzzing cannot reach.

**Grammar-Aware Mutation** — Auto-extracts protocol field definitions from dissector source code (hf_ header field arrays), builds protocol grammars, and generates structurally valid packets that exercise deep parser paths. Combined with boundary-value injection, format string attacks, and deep nesting mutations.

**Coverage-Guided Feedback** — gcov/llvm-cov integration tracks which code paths each mutated input reaches. Energy-based scheduling allocates more mutations to inputs that discover new edges. Corpus management with automatic minimization and deduplication.

**Differential Oracle** — Runs the same pcap through multiple tools. When tshark crashes but tcpdump doesn't, that's a real bug. Parse divergences are flagged for manual review.

**AI Engine** — Claude reads the C source of a parser function, identifies the specific vulnerable code pattern, and generates targeted mutations designed to trigger that exact bug. Not AI as a buzzword — the LLM literally reads the unchecked memcpy and crafts the overflow.

**Automated Triage** — Stack-hash deduplication, delta-debugging minimization, CWE classification (heap overflow → CWE-122, UAF → CWE-416, integer overflow → CWE-190), exploitability assessment with CVSS estimates, and CVE-ready report generation with vendor-specific templates.

**Live Injection & Weaponization** — Extract payloads from crash pcaps and replay them on the wire. Minimize crashes to smallest trigger. Package into reproducible PoCs with Docker one-liners.

**Honeypot Defense** — Generate realistic network traffic with embedded parser triggers. When attackers capture and analyze honeypot traffic, their own tools crash. Offense as defense.

## Why This Matters

These tools are written in C/C++, parse untrusted network input, and often run with elevated privileges. The attack surface is enormous — Wireshark alone has 3000+ dissectors with manual memory management. CVE-2026-5402 (TLS dissector RCE, CVSS 8.8) and CVE-2026-5656 (pcapng parser RCE, CVSS 7.8) prove this is not theoretical.

NetProbe's message: **your security tools are your weakest link**.

## Live Demo

1. Audience picks a protocol from a dropdown
2. NetProbe runs static analysis — shows dangerous code patterns on screen
3. Starts grammar-aware fuzzing — crashes tshark within 60 seconds
4. Auto-triages — displays CWE, CVSS, exploitability, and generates a CVE report
5. All live, all real

## Requirements

- Python 3.10+
- tshark (Wireshark CLI) — preferably ASAN-instrumented build
- Optional: Suricata, tcpdump for differential testing
- Optional: Anthropic API key for AI-guided analysis
- Docker for containerized builds
