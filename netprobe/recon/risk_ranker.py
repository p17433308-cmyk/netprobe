"""Combine all signals into a final risk ranking."""

from __future__ import annotations


class RiskRanker:
    def rank(self, parsers: list[dict]) -> list[dict]:
        for p in parsers:
            score = 0.0

            score += p.get("complexity_score", 0) * 1.5

            danger_patterns = p.get("danger_patterns", [])
            for dp in danger_patterns:
                score += dp.get("weight", 0) * 0.5

            if p.get("no_fuzz_coverage"):
                score *= 1.8

            if p.get("has_recursion"):
                score += 5.0

            if p.get("has_unchecked_alloc"):
                score += 8.0

            lines = p.get("lines", 0)
            if lines > 5000:
                score += 5.0
            elif lines > 2000:
                score += 3.0

            if not p.get("has_port_registration") and not p.get("has_heuristic"):
                score += 2.0

            p["risk_score"] = round(score, 1)

        parsers.sort(key=lambda x: x["risk_score"], reverse=True)
        return parsers
