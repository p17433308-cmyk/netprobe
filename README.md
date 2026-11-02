# NetProbe — Who Watches the Watchmen?

**Automated vulnerability discovery framework targeting the protocol parsers of network security tools.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## The Problem

Every SOC analyst, forensic examiner, and incident responder trusts their tools implicitly. Wireshark parses every packet. Suricata inspects every flow. An attacker who can crash or exploit these tools can blind the entire defense — the IDS crashes silently, the analyst's Wireshark session dies on a crafted pcap, the forensic examination fails at the evidence review stage.

These tools are written in C/C++, parse untrusted network input, and often run with elevated privileges. Wireshark alone has **3000+ dissectors** with manual memory management.

**Your security tools are your weakest link.**

## What NetProbe Does

```
netprobe recon       → Map 3000+ parsers, score risk, find OSS-Fuzz gaps
netprobe audit       → Static analysis for dangerous code patterns
netprobe fuzz        → Grammar-aware mutation fuzzing with crash detection
netprobe triage      → Deduplicate, classify CWE, assess exploitability
netprobe report      → Generate CVE-ready advisory reports
netprobe demo        → Live Arsenal demo mode
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NetProbe Pipeline                         │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  Recon   │  Audit   │   Fuzz   │  Triage  │   Report       │
│          │          │          │          │                │
│ Parser   │ Integer  │ Grammar  │ Stack    │ CVE Template   │
│ Mapper   │ Overflow │ Mutation │ Dedup    │ SARIF Output   │
│ Scoring  │ Taint    │ Encoding │ CWE Map  │ HTML Dashboard │
│ Dep Graph│ Recursion│ Nesting  │ CVSS     │ Markdown       │
│          │ Patterns │ AI-Guide │ Minimize │ JSON/CSV       │
└──────────┴──────────┴──────────┴──────────┴────────────────┘
```

## Supported Targets

| Tool | Version | Dissectors | Status |
|------|---------|------------|--------|
| Wireshark/tshark | 4.4.x | 3000+ | Primary |
| Suricata | 7.x | 60+ | Planned |
| tcpdump | 4.99+ | 200+ | Planned |
| Zeek | 6.x | 50+ | Planned |
| Snort 3 | 3.x | 300+ | Planned |

## Mutation Engines

NetProbe ships with 6 mutation strategies that chain together:

- **Grammar-Aware** — Extracts protocol field definitions from dissector source (`hf_` arrays), generates structurally valid packets
- **Deep Nesting** — Recursive protocol encapsulation to trigger stack overflows
- **Encoding** — Multi-layer encoding chains (base64, gzip, chunked) to bypass input validation
- **Format String** — Targeted `%n`/`%s` injection in string-handling dissectors
- **AI-Guided** — LLM reads the vulnerable C function and crafts the exact overflow
- **Cross-Protocol** — Embeds one protocol inside another to confuse type-detection heuristics

## ASAN Fuzzing Results

Tested against Wireshark 4.4.9 with AddressSanitizer + UndefinedBehaviorSanitizer instrumentation:

| Run | Platform | Execs | Rate | Duration | Dissectors | Crashes |
|-----|----------|-------|------|----------|------------|---------|
| Blind Mutation (Mac) | M-series Mac | 2,576 | 3/s | 15 min | 20 | 0 |
| Blind Mutation (Remote) | i9 Ultra / 130GB | 1,500,000+ | 858/s | 30 min | 20 | 0 |

**Key finding:** Blind mutation fuzzing — even at scale with ASAN instrumentation — cannot reach deep parser paths in mature code. This validates the need for coverage-guided and structure-aware fuzzing, which is NetProbe's core approach.

## Quick Start

```bash
# Install
pip install -e ".[all]"

# Reconnaissance — map Wireshark dissectors
netprobe recon --tool wireshark --source /path/to/wireshark/epan/dissectors/

# Static audit — find dangerous patterns
netprobe audit --source /path/to/wireshark/epan/dissectors/

# Fuzz a specific dissector
netprobe fuzz --target wireshark --dissector dns --seeds corpus/seeds/ --duration 300

# Triage crashes
netprobe triage --crashes corpus/crashes/

# Generate report
netprobe report --format html --output report.html
```

## ASAN Build (for deep testing)

```bash
# Clone and build ASAN-instrumented tshark
git clone --depth 1 --branch wireshark-4.4.9 https://gitlab.com/wireshark/wireshark.git
cd wireshark && mkdir build && cd build
cmake -G Ninja .. \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DBUILD_wireshark=OFF
ASAN_OPTIONS=detect_leaks=0 ninja tshark
```

## Project Structure

```
netprobe/
├── netprobe/           # Core library
│   ├── recon/          # Parser mapping & risk scoring
│   ├── audit/          # Static code analysis
│   ├── mutators/       # 6 mutation engines
│   ├── harness/        # Fuzzing orchestration
│   ├── triage/         # Crash dedup & classification
│   ├── ai/             # LLM-powered analysis
│   └── reporters/      # Output formats (CVE, SARIF, HTML)
├── grammars/           # Protocol grammar definitions
├── targets/            # Tool-specific configurations
├── corpus/
│   ├── seeds/          # Seed pcaps (11 protocols)
│   └── crashes/        # Discovered crashes
├── tests/              # Test suite
└── docs/               # Documentation & submission materials
```

## Research Context

NetProbe was developed at the DFIR Research Lab to systematically evaluate the security posture of network analysis tools. The framework demonstrates that:

1. Network security tools have a massive, under-tested attack surface
2. Blind fuzzing is insufficient against mature C parsers
3. Grammar-aware + coverage-guided approaches are required for meaningful vulnerability discovery
4. AI-assisted mutation can target specific code patterns identified by static analysis

## License

MIT
