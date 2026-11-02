"""Tests for mutation engine and mutators."""

import pytest
from netprobe.mutators.engine import MutationEngine
from netprobe.mutators.bitflip import BitFlipMutator
from netprobe.mutators.overflow import OverflowMutator
from netprobe.mutators.magic import MagicValueMutator
from netprobe.mutators.structure_aware import StructureAwareMutator


class TestMutationEngine:
    def test_default_mutators(self):
        engine = MutationEngine()
        assert len(engine.mutators) > 0

    def test_mutate_returns_list(self):
        engine = MutationEngine(mutator_names=["bitflip"])
        data = bytes(64)
        result = engine.mutate(data, count=5)
        assert isinstance(result, list)
        assert len(result) == 5

    def test_mutate_changes_data(self):
        engine = MutationEngine(mutator_names=["bitflip", "overflow", "magic"])
        data = bytes(64)
        results = engine.mutate(data, count=20)
        changed = sum(1 for r in results if r != data)
        assert changed > 0

    def test_empty_data(self):
        engine = MutationEngine(mutator_names=["bitflip"])
        result = engine.mutate(b"", count=3)
        assert isinstance(result, list)

    def test_named_mutators(self):
        engine = MutationEngine(mutator_names=["bitflip", "overflow", "magic", "structure"])
        assert len(engine.mutators) == 4


class TestBitFlipMutator:
    def test_mutate(self):
        m = BitFlipMutator()
        data = bytes(32)
        result = m.mutate(data)
        assert isinstance(result, bytes)


class TestOverflowMutator:
    def test_mutate(self):
        m = OverflowMutator()
        data = bytes(32)
        result = m.mutate(data)
        assert isinstance(result, bytes)


class TestMagicValueMutator:
    def test_mutate(self):
        m = MagicValueMutator()
        data = bytes(32)
        result = m.mutate(data)
        assert isinstance(result, bytes)


class TestStructureAwareMutator:
    def test_mutate(self):
        m = StructureAwareMutator()
        # Minimal pcap header (24 bytes) + packet
        import struct
        header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt = bytes(64)
        pkt_hdr = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
        data = header + pkt_hdr + pkt
        result = m.mutate(data)
        assert isinstance(result, bytes)
