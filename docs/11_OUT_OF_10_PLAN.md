# NetProbe — 11/10 Arsenal Plan

## The Complete Command Set

```
netprobe recon       → map parsers, score risk, find OSS-Fuzz gaps        [BUILT]
netprobe audit       → static analysis for dangerous code patterns        [BUILT]
netprobe fuzz        → mutation-based fuzzing with crash detection        [BUILT]
netprobe triage      → deduplicate, classify, assess exploitability      [BUILT]
netprobe report      → generate CVE-ready advisory reports               [BUILT]
netprobe targets     → list supported tools                              [BUILT]
netprobe demo        → Arsenal stage demo mode                           [BUILT]

netprobe diff        → differential fuzzing across 5 tools               [TODO]
netprobe inject      → live wire injection — crash tools over the network [TODO]
netprobe weaponize   → auto-generate weaponized pcaps from found CVEs    [TODO]
netprobe honeypot    → defensive traffic gen that poisons attacker tools  [TODO]
netprobe grammar     → extract + visualize protocol grammars             [TODO]
netprobe coverage    → coverage-guided fuzzing with gcov feedback        [TODO]
netprobe ai          → AI-guided code analysis + targeted mutations      [TODO]
netprobe dashboard   → launch interactive HTML results dashboard         [TODO]
```

---

## The 11/10 Features (What Makes This Legendary)

### Feature 1: Differential Fuzzing Engine (`netprobe diff`)

**What:** Send identical packets through Wireshark, Suricata, tcpdump, Zeek, Snort simultaneously.

**Why it's 11/10:**
- If one tool crashes and others don't → that's a crash bug (CVE)
- If tools parse the SAME packet DIFFERENTLY → that's a logic bug (even scarier)
- A forensic examiner using Wireshark sees different data than a SOC using Suricata
  from the SAME capture → evidence integrity nightmare
- Nobody has built this. Zero tools do cross-tool differential testing for network parsers.

**Architecture:**
```python
# netprobe/differential/
├── oracle.py          # Run same pcap through N tools, compare outputs
├── comparator.py      # Semantic comparison of parse trees (not just text diff)
├── divergence_db.py   # Track and categorize all divergences found
└── reporter.py        # "Tool A says HTTP, Tool B says garbage" reports
```

**Demo moment:** "Here's one packet. Wireshark says it's valid HTTP. Suricata doesn't parse it at all. Your IDS is blind to this traffic."

---

### Feature 2: Live Wire Injection (`netprobe inject`)

**What:** Sit on a network interface, inject crafted packets in real-time that crash
a live Wireshark/Suricata instance monitoring that network.

**Why it's 11/10:**
- Demo: "I'm going to crash your Wireshark from across the room. Right now."
- Shows the REAL attack scenario: attacker on the network blinds the SOC
- Not theoretical — uses CVEs found by the fuzzer
- Audience gasps. That's the moment people remember.

**Architecture:**
```python
# netprobe/inject/
├── crafter.py         # Build live packets from crash-triggering pcaps (scapy)
├── injector.py        # Send crafted packets on a network interface
├── target_detector.py # Detect if Wireshark/Suricata is running on the target
└── scenarios.py       # Pre-built attack scenarios (blind SOC, crash forensic, etc.)
```

**Safety:** Only works on isolated demo networks. Requires explicit --i-know-what-im-doing flag.

---

### Feature 3: Weaponized Pcap Generator (`netprobe weaponize`)

**What:** Takes a crash/CVE found by the fuzzer → auto-generates a clean, minimal,
weaponized pcap that reliably triggers it.

**Why it's 11/10:**
- Automated exploit generation from fuzzer output
- "netprobe found a heap overflow, and 30 seconds later it produced a weaponized pcap"
- Includes metadata: target tool + versions affected + CWE + CVSS estimate
- Pcap is ready for responsible disclosure PoC attachment

**Architecture:**
```python
# netprobe/weaponize/
├── minimizer.py       # Delta-debugging to smallest triggering pcap
├── stabilizer.py      # Ensure crash is reliable (100% repro rate)
├── packager.py        # Bundle: pcap + report + reproduce.sh + Dockerfile
└── validator.py       # Confirm crash across multiple tool versions
```

---

### Feature 4: Honeypot Traffic Generator (`netprobe honeypot`)

**What:** Generate network traffic that looks normal but contains payloads designed
to crash/exploit an attacker's analysis tools when they capture and open it.

**Why it's 11/10:**
- OFFENSIVE DEFENSE: Attacker sniffs your network → opens pcap in Wireshark → BOOM
- Flips the entire attack model: the defender's traffic becomes a trap
- Ties to the user's existing honeypot research (ProtocolHive)
- "We found the bugs. We weaponized them. Then we turned them into a defense."
- This is the narrative that makes the review board say "this is new thinking"

**Architecture:**
```python
# netprobe/honeypot/
├── traffic_gen.py     # Generate normal-looking traffic with embedded triggers
├── protocol_mixer.py  # Mix legitimate and weaponized packets naturally
├── stealth.py         # Make triggers look like normal protocol artifacts
├── profiles.py        # Traffic profiles: web browsing, DNS, IoT, enterprise
└── deployment.py      # Run as a service, integrate with existing honeypots
```

**Demo:** Run a web server that serves pages. An "attacker" captures the traffic.
Opens the pcap. Their Wireshark crashes. "Your analysis tool just became the victim."

---

### Feature 5: Protocol Grammar Auto-Extraction (`netprobe grammar`)

**What:** Automatically parse Wireshark dissector C source code to extract protocol
field definitions, lengths, types, and constraints → build a grammar model →
generate VALID packets that test every field boundary.

**Why it's 11/10:**
- Wireshark already has the world's best protocol database in its hf_ arrays
- We're mining THEIR code to find THEIR bugs — poetic
- Grammar-aware fuzzing finds bugs byte-flipping never will
- Generates packets that look structurally valid but have boundary values in every field

**Architecture:**
```python
# netprobe/grammar/
├── extractor.py       # Parse hf_ arrays from dissector C code (tree-sitter)
├── grammar_model.py   # Protocol grammar AST: fields, types, lengths, constraints
├── pcap_synthesizer.py # Generate valid pcaps from grammar
├── field_mutator.py   # Mutate individual grammar fields at boundaries
└── visualizer.py      # ASCII/HTML visualization of extracted grammars
```

---

### Feature 6: AI Code Auditor (`netprobe ai`)

**What:** Feed dissector source code to Claude → get back targeted mutation
strategies for specific vulnerable code paths.

**How it actually works (not buzzword AI):**
1. Extract a dissector function
2. Send to Claude: "Here's a Wireshark dissector function. Identify unchecked
   packet-derived values used in memory operations. For each, suggest a packet
   field value that would trigger the bug."
3. Claude returns: "Line 342: tvb_memcpy uses `length` from offset 12 without
   checking against buffer size 256. Set the 16-bit BE value at packet offset
   12 to 0x0200 (512) to overflow."
4. Generate that exact mutation → fuzz → crash

**Why it's 11/10:**
- Not "AI-powered" as marketing — the LLM is doing actual vulnerability research
- Dramatically reduces time-to-CVE compared to blind fuzzing
- 19/80 Arsenal USA 2026 tools used AI — this is expected now, but ours WORKS

---

## The Full Narrative Arc (Arsenal Presentation Flow)

### Act 1: "The Problem" (5 min)
- Every SOC, forensic lab, IR team trusts Wireshark/Suricata
- These tools parse untrusted data, run as root, written in C
- CVEs keep flowing: TLS RCE (8.8), pcapng RCE (7.8), Suricata UAF
- "Who watches the watchmen? Nobody. Until now."

### Act 2: "The Framework" (10 min)
- NetProbe recon: show the risk-ranked dissector list
- Static audit: show dangerous code patterns
- Grammar extraction: show auto-extracted protocol grammar
- "We mined Wireshark's own code to find Wireshark's own bugs"

### Act 3: "The Kills" (15 min)
- Fuzz campaign results: N unique crashes across M tools
- Differential results: "Same packet, different answers"
- CVE showcase: our reported vulnerabilities
- Live fuzz demo: audience picks a protocol, watch it crash

### Act 4: "The Weapon" (10 min)
- Live injection demo: crash Wireshark across the room
- Weaponized pcap generation from a crash
- "30 seconds from crash to weaponized exploit"

### Act 5: "The Defense" (10 min)
- Flip the script: honeypot mode
- Demo: attacker captures traffic → opens pcap → their tool crashes
- "We turned the vulnerability into a defense"
- "Your traffic is now a trap"

### Closing: "Who Watches the Watchmen? We Do." (5 min)
- Open source, MIT license, available today
- N CVEs found, responsibly disclosed
- Call to action: audit YOUR security tools

---

## Build Order (Remaining Sprints)

### Sprint 2: Grammar Engine (3-4 days)
- tree-sitter C parser for hf_ extraction
- Grammar model + pcap synthesizer
- Structure-aware mutations from grammar

### Sprint 3: Differential Fuzzing (2-3 days)
- Multi-tool harness orchestration
- Parse tree comparator
- Divergence database + reporter

### Sprint 4: Coverage-Guided Fuzzing (2-3 days)
- gcov/llvm-cov integration
- Edge-coverage bitmap tracking
- Energy-based corpus evolution

### Sprint 5: Live Injection + Weaponizer (3-4 days)
- Scapy packet crafter from crash pcaps
- Network injector with safety controls
- Pcap minimizer + stabilizer + packager

### Sprint 6: Honeypot Mode (2-3 days)
- Traffic generator with embedded triggers
- Protocol mixing + stealth
- Deployment as a service

### Sprint 7: AI Engine (2-3 days)
- Claude API integration for code analysis
- Targeted mutation generation from AI suggestions
- AI-written CVE reports + root cause explanations

### Sprint 8: Dashboard + Demo Mode (2-3 days)
- Interactive HTML dashboard
- Full demo pipeline: recon → audit → fuzz → crash → weaponize → inject
- AI narrator for live demos

### Sprint 9: Docker + CI + Docs (2 days)
- Dockerfiles for ASAN builds of all 5 tools
- docker-compose full stack
- 3+ pages English documentation
- Arsenal submission text + recorded demo video

### Sprint 10: CVE Hunt (ongoing)
- Run campaigns against Wireshark 4.6.x + Suricata 8.x
- Report findings to vendors
- Collect CVE numbers for Arsenal submission

---

## Success Criteria for 11/10

- [ ] 5+ real CVEs found and responsibly disclosed
- [ ] At least 1 CVE in Wireshark AND 1 in Suricata (multi-tool proof)
- [ ] Differential fuzzing finds at least 1 parsing divergence
- [ ] Live injection demo works reliably on isolated network
- [ ] Honeypot mode generates convincing traffic with embedded triggers
- [ ] AI auditor identifies at least 1 bug that blind fuzzing missed
- [ ] Grammar extraction works on 10+ Wireshark protocols
- [ ] Full demo runs start to finish in under 60 minutes
- [ ] Tool installs and runs with `pip install netprobe` in under 5 minutes
- [ ] "Holy shit" reaction from at least 1 test audience member
