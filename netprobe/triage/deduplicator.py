"""Deduplicate crashes by stack trace similarity."""

from __future__ import annotations

import hashlib


class Deduplicator:
    def __init__(self, frame_depth: int = 5):
        self.frame_depth = frame_depth

    def deduplicate(self, crashes: list[dict]) -> list[dict]:
        """Return unique crashes based on stack hash."""
        seen: dict[str, dict] = {}

        for crash in crashes:
            stack_hash = self._hash_stack(crash)
            if stack_hash not in seen:
                crash["stack_hash"] = stack_hash
                crash["duplicate_count"] = 1
                seen[stack_hash] = crash
            else:
                seen[stack_hash]["duplicate_count"] = seen[stack_hash].get("duplicate_count", 1) + 1

        return list(seen.values())

    def _hash_stack(self, crash: dict) -> str:
        frames = crash.get("stack_trace", [])
        top_frames = frames[:self.frame_depth]

        if top_frames:
            key = "|".join(top_frames)
        elif crash.get("function"):
            key = f"{crash.get('crash_type', '')}:{crash['function']}"
        else:
            key = crash.get("crash_id", "unknown")

        return hashlib.sha256(key.encode()).hexdigest()[:12]
