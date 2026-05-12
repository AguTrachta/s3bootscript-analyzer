from enum import IntEnum

from s3bootscript_analyzer.engine.formatting import (
    MISSING_FIELD,
    format_bytes,
    format_field,
    format_integer,
    format_semantic_bytes,
    format_semantic_value,
    format_value,
)


class ExampleEnum(IntEnum):
    FIRST = 1


def test_format_integer_uses_lowercase_hex() -> None:
    assert format_integer(0xABCD) == "0xabcd"


def test_format_bytes_uses_comma_separated_hex() -> None:
    assert format_bytes(b"\x01\xab\xff") == "01,ab,ff"


def test_format_bytes_marks_empty_values() -> None:
    assert format_bytes(b"") == "<empty>"


def test_format_value_uses_int_enum_names() -> None:
    assert format_value(ExampleEnum.FIRST) == "FIRST"


def test_format_value_marks_missing_fields() -> None:
    assert format_value(MISSING_FIELD) == "<missing>"
    assert format_field("address", MISSING_FIELD) == "address=<missing>"


def test_format_semantic_bytes_uses_little_endian_hex_without_separators() -> None:
    assert format_semantic_bytes(b"\x21\x00\x00\x00") == "0x00000021"
    assert format_semantic_bytes(b"") == "<empty>"
    assert format_semantic_value(b"\xaa\xbb") == "0xbbaa"
    assert format_semantic_value(ExampleEnum.FIRST) == "FIRST"
