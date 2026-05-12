from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord


def test_raw_opcode_record_payload_size_excludes_record_prefix() -> None:
    record = RawOpcodeRecord(
        opcode_id=0x02,
        length=5,
        offset=0x10,
        body=object(),
        raw_bytes=b"\x02\x00\x05\xaa\xbb",
    )

    assert record.payload_size() == 2


def test_raw_opcode_record_payload_size_never_goes_negative() -> None:
    record = RawOpcodeRecord(
        opcode_id=0xFF,
        length=2,
        offset=0x20,
        body=object(),
        raw_bytes=b"\xff\x00",
    )

    assert record.payload_size() == 0
