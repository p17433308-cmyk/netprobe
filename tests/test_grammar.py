"""Tests for grammar extraction and pcap synthesis."""

import random
import pytest
from netprobe.grammar.grammar_model import PacketTemplate, FieldSpec, grammar_to_template
from netprobe.grammar.extractor import ProtocolGrammar, ProtocolField, GrammarExtractor
from netprobe.grammar.pcap_synthesizer import PcapSynthesizer


class TestFieldSpec:
    def test_generate_fixed_size(self):
        fs = FieldSpec(name="test", field_type="FT_UINT16", size_bytes=2)
        rng = random.Random(42)
        data = fs.generate(rng)
        assert len(data) == 2

    def test_generate_boundary(self):
        fs = FieldSpec(name="test", field_type="FT_UINT32", size_bytes=4,
                       boundary_values=[0, 0xFFFFFFFF])
        rng = random.Random(42)
        data = fs.generate_boundary(rng)
        assert len(data) == 4

    def test_generate_variable_size(self):
        fs = FieldSpec(name="test", field_type="FT_BYTES", size_bytes=0)
        rng = random.Random(42)
        data = fs.generate(rng)
        assert isinstance(data, bytes)


class TestPacketTemplate:
    def test_generate(self):
        t = PacketTemplate(protocol="test", fields=[
            FieldSpec(name="a", field_type="FT_UINT8", size_bytes=1),
            FieldSpec(name="b", field_type="FT_UINT16", size_bytes=2),
        ])
        data = t.generate()
        assert len(data) == 3

    def test_generate_mutated(self):
        t = PacketTemplate(protocol="test", fields=[
            FieldSpec(name="a", field_type="FT_UINT32", size_bytes=4),
            FieldSpec(name="b", field_type="FT_UINT32", size_bytes=4),
        ])
        data = t.generate_mutated(mutation_rate=1.0)
        assert len(data) == 8


class TestGrammarToTemplate:
    def test_converts_grammar(self):
        g = ProtocolGrammar(
            protocol_name="Test Protocol",
            short_name="test",
            fields=[
                ProtocolField(name="ID", abbreviation="test.id",
                              field_type="FT_UINT16", display="BASE_DEC",
                              size_bytes=2),
            ],
        )
        t = grammar_to_template(g)
        assert t.protocol == "test"
        assert len(t.fields) == 1
        assert t.fields[0].size_bytes == 2


class TestPcapSynthesizer:
    def test_synthesize(self):
        t = PacketTemplate(protocol="test", fields=[
            FieldSpec(name="a", field_type="FT_UINT32", size_bytes=4),
        ])
        synth = PcapSynthesizer(seed=42)
        pcap = synth.synthesize(t, count=3)
        assert pcap[:4] == b"\xd4\xc3\xb2\xa1"  # pcap magic (LE)

    def test_synthesize_mutated(self):
        t = PacketTemplate(protocol="test", fields=[
            FieldSpec(name="a", field_type="FT_UINT16", size_bytes=2),
        ])
        synth = PcapSynthesizer(seed=42)
        pcaps = synth.synthesize_mutated(t, count=5)
        assert len(pcaps) == 5
        for p in pcaps:
            assert p[:4] == b"\xd4\xc3\xb2\xa1"
