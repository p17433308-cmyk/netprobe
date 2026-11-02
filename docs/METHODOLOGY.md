# NetProbe Methodology

## The Trust Attack Thesis

Network security tools — Wireshark, Suricata, Zeek, Snort, tcpdump — are the foundation of network defense. Every SOC, forensic lab, and IR team depends on them. Yet these tools:

1. **Parse untrusted input** — every packet from the network, every pcap from unknown sources
2. **Run with elevated privileges** — packet capture requires root/admin
3. **Are written in memory-unsafe languages** — C/C++ with manual memory management
4. **Are implicitly trusted** — nobody sandboxes their Wireshark

## Attack Scenarios

- **Blind the SOC** — crash the IDS during an attack; the alert never fires
- **Compromise the analyst** — RCE via a crafted pcap opened for investigation
- **Poison forensics** — crash during evidence analysis, corrupt the investigation
- **Lateral movement** — exploit monitoring servers running tshark/Suricata in privileged positions

## Discovery Pipeline

### Phase 1: Reconnaissance

Map the attack surface. For Wireshark:
- 3000+ C dissectors in `epan/dissectors/`
- Each registers via `proto_register_protocol()`
- Each uses `tvb_*` APIs to read packet bytes

Score each dissector by:
- Lines of code (complexity proxy)
- Dangerous API call count (`tvb_memcpy`, `wmem_alloc`, `memcpy`)
- Presence of recursion (`call_dissector` without depth guard)
- OSS-Fuzz coverage (port-dependent dissectors are unreachable)
- Recent modifications (regression risk)

### Phase 2: Static Analysis

Pattern-match for known-dangerous constructs:
- `tvb_memcpy(tvb, buf, offset, len)` where `len` is packet-controlled without bounds check
- `wmem_alloc(scope, count * elem_size)` without integer overflow check
- `for(i = 0; i < tvb_get_guint16(tvb, offset); i++)` — loop bound from packet
- Recursive `call_dissector()` without depth counter
- `sprintf` / `sscanf` with packet data

### Phase 3: Grammar-Aware Fuzzing

Extract protocol structure from dissector source:
- Parse `hf_` header field arrays for field types, sizes, encodings
- Build protocol grammar model with field dependencies
- Generate structurally valid packets that pass initial parsing
- Apply targeted mutations to specific fields

Coverage-guided feedback:
- gcov tracks which lines/branches each input reaches
- Energy scheduling prioritizes inputs that discover new edges
- Corpus evolves toward maximum code coverage

### Phase 4: Differential Testing

Run the same pcap through multiple tools:
- tshark (Wireshark CLI)
- tcpdump
- suricata (pcap replay mode)

Divergences indicate bugs:
- **Crash divergence**: one tool crashes, others don't → exploitable bug
- **Parse divergence**: tools disagree on protocol → potential logic bug

### Phase 5: AI-Guided Analysis

Claude reads the C source of high-risk functions:
- Identifies specific vulnerable patterns
- Suggests targeted mutations for exact code paths
- Explains crash root causes in CVE-report language

### Phase 6: Triage and Disclosure

For each unique crash:
1. Deduplicate by stack trace hash
2. Minimize via delta debugging (smallest triggering pcap)
3. Classify CWE and estimate CVSS
4. Assess exploitability (DoS vs. info leak vs. RCE)
5. Generate vendor-specific CVE report
6. Responsible disclosure to vendor security team

## Responsible Disclosure Contacts

| Tool | Contact | CNA |
|------|---------|-----|
| Wireshark | security@wireshark.org | Self (own CNA) |
| Suricata | security@openinfosecfoundation.org | OISF |
| tcpdump | security@tcpdump.org | MITRE |
| Zeek | security@zeek.org | MITRE |
| Snort | security@snort.org | Cisco |
