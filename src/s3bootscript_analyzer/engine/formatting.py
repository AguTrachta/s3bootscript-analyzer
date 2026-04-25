"""Shared text formatting helpers for IR rendering."""

from __future__ import annotations

from enum import IntEnum
from typing import Literal

from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord

HEX_PREFIX = "0x"
BYTE_SEPARATOR = ","
EMPTY_BYTES_TEXT = "<empty>"
MISSING_FIELD_TEXT = "<missing>"
HEX_DIGITS_PER_BYTE = 2
LITTLE_ENDIAN: Literal["little"] = "little"


class MissingField:
    """Sentinel used when a decoded body does not expose an expected field."""


MISSING_FIELD = MissingField()


def format_record_prefix(record: RawOpcodeRecord, mnemonic: str, verbose: bool) -> str:
    if not verbose:
        return f"{format_integer(record.offset)}: {mnemonic}"
    return _format_verbose_record_prefix(record, mnemonic)


def _format_verbose_record_prefix(record: RawOpcodeRecord, mnemonic: str) -> str:
    return (
        f"{format_integer(record.offset)}: {mnemonic} "
        f"opcode={format_integer(record.opcode_id)} "
        f"length={record.length} payload={record.payload_size()}"
    )


def format_field(name: str, value: object) -> str:
    return f"{name}={format_value(value)}"


def format_value(value: object) -> str:
    if isinstance(value, MissingField):
        return MISSING_FIELD_TEXT
    return _format_present_value(value)


def _format_present_value(value: object) -> str:
    if isinstance(value, bytes):
        return format_bytes(value)
    return _format_scalar(value)


def _format_scalar(value: object) -> str:
    if isinstance(value, IntEnum):
        return value.name
    if isinstance(value, int):
        return format_integer(value)
    return str(value)


def format_integer(value: int) -> str:
    return f"{HEX_PREFIX}{value:x}"


def format_bytes(value: bytes) -> str:
    text = value.hex(BYTE_SEPARATOR)
    return text or EMPTY_BYTES_TEXT


def format_semantic_value(value: object) -> str:
    match value:
        case bytes():
            return format_semantic_bytes(value)
        case IntEnum():
            return value.name
        case int():
            return format_integer(value)
        case _:
            return str(value)


def format_semantic_bytes(value: bytes) -> str:
    if not value:
        return EMPTY_BYTES_TEXT
    integer_value = int.from_bytes(value, byteorder=LITTLE_ENDIAN, signed=False)
    width = len(value) * HEX_DIGITS_PER_BYTE
    return f"{HEX_PREFIX}{integer_value:0{width}x}"
