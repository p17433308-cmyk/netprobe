"""AI-powered mutation advisor — LLM reads code and suggests targeted mutations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class MutationSuggestion:
    target_function: str
    field_name: str
    mutation_type: str
    rationale: str
    payload_hint: bytes | None = None
    confidence: float = 0.0


class AIMutationAdvisor:
    """Use Claude to analyze parser code and suggest targeted mutations."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-5-5"):
        self.api_key = api_key
        self.model = model

    def suggest_for_function(self, source_code: str, function_name: str) -> list[MutationSuggestion]:
        prompt = f"""Analyze this C parser function for vulnerabilities. For each potential bug,
suggest a specific mutation (exact bytes/values) that would trigger it.

Function: {function_name}
```c
{source_code[:8000]}
```

For each vulnerability found, provide:
1. The field to target
2. The exact mutation (overflow value, format string, etc.)
3. Why this triggers the bug
4. Confidence (0-1)

Format as structured analysis."""

        response = self._call_api(prompt)
        return self._parse_suggestions(response, function_name)

    def suggest_for_file(self, file_path: Path) -> list[MutationSuggestion]:
        content = file_path.read_text(errors="replace")
        prompt = f"""Analyze this network protocol parser source file for vulnerabilities.
Identify the most dangerous functions and suggest targeted fuzzing mutations.

File: {file_path.name}
```c
{content[:12000]}
```

Focus on:
- Unchecked buffer copies (tvb_memcpy, memcpy)
- Integer overflows in size calculations
- Unbounded loops with packet-controlled bounds
- Recursive dissector calls without depth limits
- Format string vulnerabilities

For each finding, suggest an exact byte sequence or value to trigger it."""

        response = self._call_api(prompt)
        return self._parse_suggestions(response, file_path.stem)

    def _call_api(self, prompt: str) -> str:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as e:
            return f"API error: {e}"

    def _parse_suggestions(self, response: str, context: str) -> list[MutationSuggestion]:
        suggestions = []
        current = None

        for line in response.split("\n"):
            line = line.strip()
            if not line:
                if current:
                    suggestions.append(current)
                    current = None
                continue

            if any(kw in line.lower() for kw in ("vulnerability", "bug", "overflow", "finding")):
                if current:
                    suggestions.append(current)
                current = MutationSuggestion(
                    target_function=context,
                    field_name="",
                    mutation_type="unknown",
                    rationale=line,
                )

            if current:
                if "field" in line.lower():
                    current.field_name = line.split(":", 1)[-1].strip() if ":" in line else line
                if "mutation" in line.lower() or "payload" in line.lower():
                    current.mutation_type = line.split(":", 1)[-1].strip() if ":" in line else line
                if "confidence" in line.lower():
                    try:
                        current.confidence = float(line.split(":")[-1].strip().rstrip("%")) / 100
                    except ValueError:
                        pass

        if current:
            suggestions.append(current)

        return suggestions
