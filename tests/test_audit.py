"""Tests for audit modules."""

import pytest
from netprobe.audit.pattern_scanner import PatternScanner, VULNERABILITY_PATTERNS


class TestPatternScanner:
    def test_scanner_init(self):
        assert len(VULNERABILITY_PATTERNS) > 0

    def test_scan_nonexistent_file(self):
        s = PatternScanner()
        results = s.scan_file("/nonexistent/file.c")
        assert results == []

    def test_detects_memcpy(self, tmp_path):
        code = tmp_path / "test.c"
        code.write_text("""
void bad_func(char *dst, char *src, int n) {
    int len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    memcpy(dst, src, len);
}
""")
        s = PatternScanner()
        results = s.scan_file(str(code))
        assert len(results) > 0
