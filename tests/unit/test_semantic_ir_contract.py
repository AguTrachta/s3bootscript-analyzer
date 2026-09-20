"""Executable contract for the matcher-facing S3 semantic IR document."""

from types import SimpleNamespace
from typing import Any

import pytest

from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawOpcodeRecord, RawTableHeader

semantic_ir = pytest.importorskip(
    "s3bootscript_analyzer.ir.semantic",
    reason="SemanticIrDocument is the next production increment",
)
SemanticIrBuilder: Any = semantic_ir.SemanticIrBuilder
SemanticSourceReference: Any = semantic_ir.SemanticSourceReference


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


def test_builder_returns_immutable_collections() -> None:
    document = SemanticIrBuilder().build(_raw_script())

    assert isinstance(document.source_map, tuple)
    assert isinstance(document.diagnostics, tuple)


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
