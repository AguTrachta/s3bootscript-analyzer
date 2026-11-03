"""Bounded properties for public parser evidence and semantic source references."""

from dataclasses import dataclass
from pathlib import Path
from struct import Struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from s3bootscript_analyzer.errors import RawParseError
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.ir.semantic import SemanticIrBuilder, SemanticSourceReference
from s3bootscript_analyzer.parsers.kaitai import KaitaiBootScriptRawParser
from s3bootscript_analyzer.parsers.raw import RawTableHeader

pytestmark = pytest.mark.property

# Test-only wire encoding and expectations are independent of production helpers.
HEADER = Struct("<HBHIHH")
MEM_WRITE = Struct("<HBIIQ")
HEADER_OPCODE = 0xAA
MEM_WRITE_OPCODE = 0x02
HEADER_VERSION = 1
BYTE_WIDTH = 0
OPCODE_SIZE = 2
TERMINATE = bytes.fromhex("ff 00 03")
MAX_RECORDS = 16
MAX_PAYLOAD_SIZE = 16
MAX_ADDRESS = (1 << 64) - 1


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    payload: bytes

    def encode(self) -> bytes:
        return (
            MEM_WRITE.pack(
                MEM_WRITE_OPCODE,
                MEM_WRITE.size + len(self.payload),
                BYTE_WIDTH,
                len(self.payload),
                self.address,
            )
            + self.payload
        )

    def expected_fields(self) -> dict[str, int | tuple[int, ...]]:
        return {
            "width": BYTE_WIDTH,
            "count": len(self.payload),
            "address": self.address,
            "buffer": tuple(self.payload),
        }


@dataclass(frozen=True)
class EncodedSpan:
    offset: int
    data: bytes


@dataclass(frozen=True)
class EncodedScript:
    data: bytes
    spans: tuple[EncodedSpan, ...]


def _encode_script(records: tuple[bytes, ...]) -> EncodedScript:
    offset = HEADER.size
    spans = []
    for record in records:
        spans.append(EncodedSpan(offset, record))
        offset += len(record)
    header = HEADER.pack(HEADER_OPCODE, HEADER.size, HEADER_VERSION, offset, 0, 0)
    return EncodedScript(header + b"".join(records), tuple(spans))


WRITES = st.builds(
    MemoryWrite,
    address=st.integers(min_value=0, max_value=MAX_ADDRESS),
    payload=st.binary(min_size=1, max_size=MAX_PAYLOAD_SIZE),
)
ENDINGS: st.SearchStrategy[tuple[bytes, ...]] = st.sampled_from([(), (TERMINATE,)])


def _header_prefix(length: int) -> bytes:
    return _encode_script(()).data[:length]


def _truncated_write(write: MemoryWrite) -> st.SearchStrategy[bytes]:
    record = write.encode()
    data = _encode_script((record,)).data
    return st.integers(min_value=1, max_value=len(record) - 1).map(
        lambda length: data[: HEADER.size + length]
    )


@given(writes=st.lists(WRITES, max_size=MAX_RECORDS), ending=ENDINGS)
def test_valid_scripts_preserve_fields_bytes_and_record_bounds(
    writes: list[MemoryWrite], ending: tuple[bytes, ...]
) -> None:
    script = _encode_script(tuple(map(MemoryWrite.encode, writes)) + ending)

    parsed = KaitaiBootScriptRawParser().parse(
        BinarySource(path=Path("generated.bin"), data=script.data)
    )

    assert parsed.table_header == RawTableHeader(
        magic=HEADER_OPCODE,
        length=HEADER.size,
        version=HEADER_VERSION,
        table_length=len(script.data),
    )
    for record, expected in zip(parsed.records, script.spans, strict=True):
        assert record.opcode_id == int.from_bytes(expected.data[:OPCODE_SIZE], "little")
        assert record.offset == expected.offset
        assert record.length == len(expected.data)
        assert record.raw_bytes == expected.data
        assert HEADER.size <= record.offset < record.offset + record.length <= len(script.data)
    assert tuple(
        record.fields for record in SemanticIrBuilder().build(parsed).records[: len(writes)]
    ) == tuple(write.expected_fields() for write in writes)


@given(
    data=st.one_of(
        st.integers(min_value=1, max_value=HEADER.size - 1).map(_header_prefix),
        WRITES.flatmap(_truncated_write),
        WRITES.map(MemoryWrite.encode),
    )
)
def test_partial_fields_and_non_header_leading_records_raise_public_error(data: bytes) -> None:
    source = BinarySource(path=Path("invalid.bin"), data=data)

    with pytest.raises(RawParseError):
        KaitaiBootScriptRawParser().parse(source)


@given(write=WRITES)
def test_duplicate_writes_keep_distinct_origins_across_an_unannotated_record(
    write: MemoryWrite,
) -> None:
    script = _encode_script((write.encode(), TERMINATE, write.encode()))

    document = SemanticIrBuilder().build(
        KaitaiBootScriptRawParser().parse(
            BinarySource(path=Path("duplicates.bin"), data=script.data)
        )
    )

    lines = document.text.splitlines()
    assert len(lines) == 2
    assert lines[0] == lines[1]
    assert document.source_map == (
        SemanticSourceReference(
            semantic_line=1, record_index=0, opcode_offset=script.spans[0].offset
        ),
        SemanticSourceReference(
            semantic_line=2, record_index=2, opcode_offset=script.spans[2].offset
        ),
    )
    assert tuple(document.source_for_line(line) for line in (1, 2)) == document.source_map
    assert tuple(record.record_index for record in document.records) == (0, 1, 2)
    for record, expected in zip(document.records, script.spans, strict=True):
        assert record.offset == expected.offset
        assert record.raw_bytes == expected.data
    assert document.records[1].opcode == "TERMINATE"
    assert document.records[1].fields == {}
