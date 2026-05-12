from types import SimpleNamespace

from s3bootscript_analyzer.engine.decoders import (
    OPCODE_METADATA,
    OPCODE_METADATA_BY_ID,
    MemWriteDecoder,
    UnknownOpcodeDecoder,
)
from s3bootscript_analyzer.engine.factory import DEFAULT_DECODER_FACTORIES, build_default_registry
from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.engine.registry import OpcodeDecoderRegistry
from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord


def test_known_opcode_decoder_renders_fields() -> None:
    record = RawOpcodeRecord(
        opcode_id=int(OpcodeId.MEM_WRITE),
        length=21,
        offset=0x24,
        body=SimpleNamespace(
            width=OpcodeId.IO_WRITE, count=1, address=0xD0B30000, buffer=b"\x01\x00"
        ),
        raw_bytes=b"\x02\x00\x15" + b"\x00" * 18,
    )

    decoded = MemWriteDecoder().decode(record)

    assert decoded == "0x24: MEM_WRITE width=IO_WRITE count=0x1 address=0xd0b30000 buffer=01,00"


def test_unknown_opcode_decoder_renders_raw_bytes() -> None:
    record = RawOpcodeRecord(
        opcode_id=0x77,
        length=4,
        offset=0x40,
        body=object(),
        raw_bytes=b"\x77\x00\x04\xaa",
    )

    assert UnknownOpcodeDecoder().decode(record) == "0x40: UNKNOWN raw=77,00,04,aa"


def test_registry_uses_unknown_opcode_fallback() -> None:
    record = RawOpcodeRecord(
        opcode_id=0x77,
        length=3,
        offset=0x10,
        body=object(),
        raw_bytes=b"\x77\x00\x03",
    )

    assert OpcodeDecoderRegistry().decode(record) == "0x10: UNKNOWN raw=77,00,03"


def test_registry_uses_registered_decoder_with_verbose_prefix() -> None:
    record = RawOpcodeRecord(
        opcode_id=int(OpcodeId.TERMINATE),
        length=3,
        offset=0x5C8,
        body=object(),
        raw_bytes=b"\xff\x00\x03",
    )

    decoded = build_default_registry().decode(record, verbose=True)

    assert decoded == "0x5c8: TERMINATE opcode=0xff length=3 payload=0"


def test_opcode_metadata_matches_default_registry_factories() -> None:
    metadata_ids = {metadata.opcode_id for metadata in OPCODE_METADATA}
    factory_ids = {int(decoder_factory.opcode_id) for decoder_factory in DEFAULT_DECODER_FACTORIES}

    assert metadata_ids == factory_ids
    assert set(OPCODE_METADATA_BY_ID) == metadata_ids
