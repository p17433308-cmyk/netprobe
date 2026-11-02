"""Tests for harness modules."""

import pytest
from netprobe.harness.base import BaseHarness, ExecutionResult
from netprobe.harness.sanitizer_parser import parse_sanitizer_output


class TestExecutionResult:
    def test_basic_result(self):
        r = ExecutionResult(
            pcap_path="/tmp/test.pcap",
            return_code=0,
            stdout="",
            stderr="",
            duration=0.5,
            timed_out=False,
            crashed=False,
        )
        assert not r.crashed
        assert not r.timed_out


class TestSanitizerParser:
    def test_parse_asan_heap_overflow(self):
        stderr = """
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001c at pc 0x7f1234 bp 0x7fff sp 0x7ffc
WRITE of size 4 at 0x60200000001c thread T0
    #0 0x7f1234 in dissect_dns packet-dns.c:1234
    #1 0x7f5678 in call_dissector packet.c:567
    #2 0x7fabcd in epan_dissect epan.c:890
"""
        result = parse_sanitizer_output(stderr)
        assert result is not None
        assert result.error_type == "heap-buffer-overflow"

    def test_parse_ubsan(self):
        stderr = """
packet-smb.c:42:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x1234 in dissect_smb packet-smb.c:42
"""
        result = parse_sanitizer_output(stderr)
        assert result is not None

    def test_no_sanitizer_output(self):
        result = parse_sanitizer_output("normal output with no errors")
        assert result is None
