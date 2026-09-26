"""Executable contract for the matcher-facing S3 semantic IR document."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.parsers.kaitai import KaitaiBootScriptRawParser
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawOpcodeRecord, RawTableHeader

semantic_ir = pytest.importorskip(
    "s3bootscript_analyzer.ir.semantic",
    reason="SemanticIrDocument is the next production increment",
)
SemanticIrBuilder: Any = semantic_ir.SemanticIrBuilder
SemanticSourceReference: Any = semantic_ir.SemanticSourceReference
SAMPLE_BINARY = Path(__file__).resolve().parents[2] / "samples/binaries/s3bootscript.bin"


def test_builder_preserves_existing_semantic_text() -> None:
    document = SemanticIrBuilder().build(_raw_script())

    assert document.plugin_id == "s3bootscript"
    assert document.text == "mem[0x1000] <- 0x0001\nmem[0x1000] <- 0x0001\n"


def test_builder_maps_semantic_lines_to_distinct_binary_records() -> None:
    document = SemanticIrBuilder().build(_raw_script())

    assert document.source_map == (
        SemanticSourceReference(semantic_line=1, record_index=0, opcode_offset=0x0D),
        SemanticSourceReference(semantic_line=2, record_index=2, opcode_offset=0x30),
    )
    assert document.source_for_line(1) == document.source_map[0]
    assert document.source_for_line(2) == document.source_map[1]


@pytest.mark.parametrize("line", [0, 3])
def test_builder_rejects_lines_outside_the_semantic_document(line: int) -> None:
    document = SemanticIrBuilder().build(_raw_script())

    with pytest.raises(IndexError):
        document.source_for_line(line)


def test_builder_keeps_distinct_raw_facts_for_identical_writes_and_terminate() -> None:
    document = SemanticIrBuilder().build(_raw_script())

    assert tuple(record.record_index for record in document.records) == (0, 1, 2)
    assert tuple(record.offset for record in document.records) == (0x0D, 0x22, 0x30)
    assert document.records[0].fields == {
        "width": "uint16",
        "count": 1,
        "address": 0x1000,
        "buffer": (1, 0),
    }
    assert document.records[0].raw_bytes == document.records[2].raw_bytes
    assert document.records[1].opcode == "TERMINATE"
    assert document.records[1].fields == {}
    assert document.records[1].raw_bytes


def test_builder_snapshots_mutable_source_fields() -> None:
    buffer = [1, 0]
    script = _raw_script()
    cast(SimpleNamespace, script.records[0].body).buffer = buffer
    document = SemanticIrBuilder().build(script)

    buffer[0] = 255
    script.records.clear()

    assert document.records[0].fields["buffer"] == (1, 0)
    with pytest.raises(TypeError):
        cast(dict[str, object], document.records[0].fields)["count"] = 2


def test_real_sample_preserves_encoded_write_facts_and_unprojected_terminate() -> None:
    source = BinarySource(path=SAMPLE_BINARY, data=SAMPLE_BINARY.read_bytes())
    document = SemanticIrBuilder().build(KaitaiBootScriptRawParser().parse(source))

    assert len(document.records) == 63
    write = document.records[1]
    assert write.offset == 0x24
    assert write.opcode == "MEM_WRITE"
    assert write.fields == {
        "width": 1,
        "count": 1,
        "address": 0xD0B30000,
        "buffer": (1, 0),
    }
    assert write.raw_bytes == source.data[write.offset : write.offset + write.length]
    assert document.records[-1].opcode == "TERMINATE"
    assert document.records[-1].record_index == 62


def _raw_script() -> RawBootScript:
    body = SimpleNamespace(width="uint16", count=1, address=0x1000, buffer=b"\x01\x00")
    return RawBootScript(
        table_header=RawTableHeader(magic=0xAA, length=13, version=1, table_length=69),
        records=[
            _record(OpcodeId.MEM_WRITE, body, offset=0x0D),
            _record(OpcodeId.TERMINATE, object(), offset=0x22),
            _record(OpcodeId.MEM_WRITE, body, offset=0x30),
        ],
    )


def _record(opcode_id: OpcodeId, body: object, offset: int) -> RawOpcodeRecord:
    return RawOpcodeRecord(
        opcode_id=int(opcode_id),
        length=21,
        offset=offset,
        body=body,
        raw_bytes=int(opcode_id).to_bytes(2, "little") + b"\x15" + b"\x00" * 18,
    )
