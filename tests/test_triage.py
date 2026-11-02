"""Tests for triage modules."""

import pytest
from netprobe.triage.deduplicator import Deduplicator
from netprobe.triage.classifier import CWEClassifier
from netprobe.triage.exploitability import ExploitabilityAssessor


class TestDeduplicator:
    def test_dedup_identical(self):
        d = Deduplicator()
        crashes = [
            {"stack_trace": ["frame1", "frame2", "frame3"]},
            {"stack_trace": ["frame1", "frame2", "frame3"]},
        ]
        unique = d.deduplicate(crashes)
        assert len(unique) == 1

    def test_dedup_different(self):
        d = Deduplicator()
        crashes = [
            {"stack_trace": ["frameA", "frameB"]},
            {"stack_trace": ["frameX", "frameY"]},
        ]
        unique = d.deduplicate(crashes)
        assert len(unique) == 2

    def test_empty_input(self):
        d = Deduplicator()
        assert d.deduplicate([]) == []


class TestCWEClassifier:
    def test_heap_overflow(self):
        c = CWEClassifier()
        crash = {"crash_type": "heap-buffer-overflow"}
        c.classify(crash)
        assert crash.get("cwe") == "CWE-122"

    def test_use_after_free(self):
        c = CWEClassifier()
        crash = {"crash_type": "heap-use-after-free"}
        c.classify(crash)
        assert crash.get("cwe") == "CWE-416"

    def test_null_deref(self):
        c = CWEClassifier()
        crash = {"crash_type": "null-dereference"}
        c.classify(crash)
        assert "476" in crash.get("cwe", "")

    def test_unknown_type(self):
        c = CWEClassifier()
        crash = {"crash_type": "something-weird"}
        c.classify(crash)
        assert "cwe" in crash


class TestExploitabilityAssessor:
    def test_uaf_is_high(self):
        a = ExploitabilityAssessor()
        crash = {"crash_type": "heap-use-after-free", "asan_report": ""}
        report = a.assess(crash)
        assert report.level == "high"
        assert report.rce_potential is True

    def test_null_deref_is_low(self):
        a = ExploitabilityAssessor()
        crash = {"crash_type": "null-dereference", "asan_report": ""}
        report = a.assess(crash)
        assert report.level == "low"
        assert report.dos_only is True

    def test_heap_write_is_high(self):
        a = ExploitabilityAssessor()
        crash = {"crash_type": "heap-buffer-overflow",
                 "asan_report": "WRITE of size 16"}
        report = a.assess(crash)
        assert report.rce_potential is True
        assert report.cvss_base >= 8.0
