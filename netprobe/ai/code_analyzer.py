"""AI-powered parser code analysis using Claude API."""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel


@dataclass
class AIFinding:
    function_name: str
    file_path: str
    vulnerability_type: str
    severity: str
    description: str
    suggested_mutation: str
    confidence: float
    line_range: tuple[int, int] | None = None


class AICodeAnalyzer:
    """Use Claude to analyze parser source code for vulnerabilities."""

    SYSTEM_PROMPT = """You are an expert vulnerability researcher specializing in C/C++ parser code,
particularly network protocol parsers like Wireshark dissectors, Suricata parsers, and tcpdump printers.

Analyze the provided parser function for memory safety vulnerabilities. Focus on:
1. Buffer overflows (heap and stack) — unchecked memcpy, tvb_memcpy with packet-controlled lengths
2. Integer overflows — multiplication without overflow check, packet-controlled loop bounds
3. Use-after-free — freed memory accessed via dangling pointers
4. Null pointer dereferences — unchecked return values from allocation/lookup
5. Uncontrolled recursion — recursive dissector calls without depth limits
6. Format string bugs — user-controlled format specifiers

For each finding, provide:
- The specific vulnerable code pattern
- Why it's exploitable
- A targeted mutation strategy (specific bytes/fields to manipulate)
- Severity estimate (critical/high/medium/low)

Respond in JSON format."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-5-5"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise RuntimeError(
                    "anthropic package required. Install with: pip install anthropic"
                )
        return self._client

    def analyze_function(self, source_code: str, file_path: str = "",
                         function_name: str = "") -> list[AIFinding]:
        """Analyze a single function for vulnerabilities."""
        client = self._get_client()

        prompt = f"""Analyze this parser function for memory safety vulnerabilities:

File: {file_path}
Function: {function_name}

```c
{source_code[:8000]}
```

Return a JSON array of findings. Each finding:
{{
  "function_name": "...",
  "vulnerability_type": "buffer_overflow|integer_overflow|use_after_free|null_deref|recursion|format_string",
  "severity": "critical|high|medium|low",
  "description": "...",
  "suggested_mutation": "description of what bytes/fields to mutate to trigger this",
  "confidence": 0.0-1.0,
  "line_start": null,
  "line_end": null
}}

If no vulnerabilities found, return an empty array []."""

        response = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        return self._parse_response(response.content[0].text, file_path)

    def analyze_file(self, file_path: Path, console: Console | None = None) -> list[AIFinding]:
        """Analyze all functions in a parser source file."""
        source = file_path.read_text(errors="replace")

        if len(source) > 50000:
            chunks = self._split_functions(source)
        else:
            chunks = [source]

        findings = []
        for i, chunk in enumerate(chunks):
            if console:
                console.print(f"  Analyzing chunk {i + 1}/{len(chunks)}...")
            try:
                chunk_findings = self.analyze_function(
                    chunk, str(file_path), f"chunk_{i}"
                )
                findings.extend(chunk_findings)
            except Exception as e:
                if console:
                    console.print(f"  [yellow]AI analysis error: {e}[/yellow]")

        return findings

    def suggest_mutations(self, source_code: str, crash_info: dict) -> list[dict]:
        """Ask AI to suggest targeted mutations based on code + crash context."""
        client = self._get_client()

        prompt = f"""Given this parser code and a crash report, suggest 5 targeted mutation strategies
to find MORE vulnerabilities in similar code paths.

Crash info:
- Type: {crash_info.get('crash_type', 'unknown')}
- CWE: {crash_info.get('cwe', 'unknown')}
- Function: {crash_info.get('function', 'unknown')}

Code:
```c
{source_code[:6000]}
```

Return JSON array of mutation strategies:
[{{"field": "...", "mutation": "...", "rationale": "...", "priority": 1-5}}]"""

        response = client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            text = response.content[0].text
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except (json.JSONDecodeError, IndexError):
            pass
        return []

    def explain_crash(self, crash_info: dict, source_snippet: str = "") -> str:
        """Generate a human-readable crash explanation."""
        client = self._get_client()

        prompt = f"""Explain this crash in plain English for a CVE report:

Crash type: {crash_info.get('crash_type', 'unknown')}
CWE: {crash_info.get('cwe', 'unknown')}
Function: {crash_info.get('function', 'unknown')}
Stack trace: {crash_info.get('stack_trace', 'N/A')}
ASAN report: {crash_info.get('asan_report', 'N/A')[:2000]}

Source code context:
```c
{source_snippet[:3000]}
```

Write 2-3 paragraphs: what happened, why it's dangerous, and what an attacker could do."""

        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text

    def _parse_response(self, text: str, file_path: str) -> list[AIFinding]:
        """Parse Claude's JSON response into AIFinding objects."""
        try:
            start = text.find("[")
            end = text.rfind("]") + 1
            if start < 0 or end <= start:
                return []
            data = json.loads(text[start:end])
        except json.JSONDecodeError:
            return []

        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            findings.append(AIFinding(
                function_name=item.get("function_name", "unknown"),
                file_path=file_path,
                vulnerability_type=item.get("vulnerability_type", "unknown"),
                severity=item.get("severity", "medium"),
                description=item.get("description", ""),
                suggested_mutation=item.get("suggested_mutation", ""),
                confidence=float(item.get("confidence", 0.5)),
                line_range=(item.get("line_start"), item.get("line_end"))
                if item.get("line_start") else None,
            ))
        return findings

    def _split_functions(self, source: str) -> list[str]:
        """Naive split of C source into function-sized chunks."""
        lines = source.split("\n")
        chunks = []
        current: list[str] = []
        brace_depth = 0

        for line in lines:
            current.append(line)
            brace_depth += line.count("{") - line.count("}")

            if brace_depth <= 0 and len(current) > 10:
                chunks.append("\n".join(current))
                current = []
                brace_depth = 0

        if current:
            chunks.append("\n".join(current))

        return chunks if chunks else [source]
