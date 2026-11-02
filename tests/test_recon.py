"""Tests for recon modules."""

import pytest
from netprobe.recon.risk_ranker import RiskRanker
from netprobe.recon.complexity_scorer import ComplexityScorer


class TestRiskRanker:
    def test_large_file_bonus(self):
        r = RiskRanker()
        parsers = [
            {"lines": 6000, "complexity_score": 0},
            {"lines": 3000, "complexity_score": 0},
            {"lines": 500, "complexity_score": 0},
        ]
        r.rank(parsers)
        assert parsers[0]["risk_score"] > parsers[1]["risk_score"]
        assert parsers[1]["risk_score"] > parsers[2]["risk_score"]

    def test_5000_lines_beats_2000(self):
        r = RiskRanker()
        big = [{"lines": 6000, "complexity_score": 0}]
        med = [{"lines": 3000, "complexity_score": 0}]
        r.rank(big)
        r.rank(med)
        assert big[0]["risk_score"] > med[0]["risk_score"]

    def test_no_fuzz_coverage_multiplier(self):
        r = RiskRanker()
        covered = [{"complexity_score": 10, "no_fuzz_coverage": False}]
        uncovered = [{"complexity_score": 10, "no_fuzz_coverage": True}]
        r.rank(covered)
        r.rank(uncovered)
        assert uncovered[0]["risk_score"] > covered[0]["risk_score"]

    def test_recursion_bonus(self):
        r = RiskRanker()
        parsers = [{"complexity_score": 0, "has_recursion": True}]
        r.rank(parsers)
        assert parsers[0]["risk_score"] >= 5.0

    def test_empty_list(self):
        r = RiskRanker()
        result = r.rank([])
        assert result == []

    def test_sorted_descending(self):
        r = RiskRanker()
        parsers = [
            {"complexity_score": 1},
            {"complexity_score": 10},
            {"complexity_score": 5},
        ]
        r.rank(parsers)
        scores = [p["risk_score"] for p in parsers]
        assert scores == sorted(scores, reverse=True)


class TestComplexityScorer:
    def test_scorer_creates_scores(self):
        scorer = ComplexityScorer()
        parsers = [{"path": "/dev/null", "filename": "test.c", "lines": 100}]
        result = scorer.score_all(parsers)
        assert all("complexity_score" in p for p in result)
