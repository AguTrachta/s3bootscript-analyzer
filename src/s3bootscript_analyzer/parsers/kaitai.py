"""Kaitai-backed raw parser adapter."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Any, SupportsInt, cast

from kaitaistruct import KaitaiStructError

from s3bootscript_analyzer.errors import RawParseError
from s3bootscript_analyzer.ingest.source import BinarySource
from s3bootscript_analyzer.parsers.raw import (
    RawBootScript,
    RawOpcodeRecord,
    RawTableHeader,
)

GENERATED_MODULE_NAME = "s3bootscript_analyzer.parsers.generated.s3_boot_script_analizer"
GENERATED_CLASS_NAME = "S3BootScriptAnalizer"
KAITAI_STREAM_CLASS_NAME = "KaitaiStream"
BYTES_IO_CLASS_NAME = "BytesIO"
HEADER_OPCODE_ID = 0xAA
FIRST_RECORD_INDEX = 0
FIRST_OPCODE_OFFSET = 0
NEXT_RECORD_STEP = 1
RECORDS_ATTRIBUTE = "records"
BODY_ATTRIBUTE = "body"
OPCODE_ATTRIBUTE = "opcode"


class KaitaiBootScriptRawParser:
    """Use generated Kaitai code and adapt it into raw domain records."""

    def parse(self, source: BinarySource) -> RawBootScript:
        generated_script = _parse_generated_script(source.data)
        generated_records = _generated_records(generated_script)
        table_header = _read_table_header(generated_records)
        records = _read_opcode_records(source.data, generated_records)
        return RawBootScript(table_header=table_header, records=records)


def _parse_generated_script(data: bytes) -> Any:
    module = _generated_module()
    stream = _generated_stream(module, data)
    generated_class = getattr(module, GENERATED_CLASS_NAME)
    try:
        return generated_class(stream)
    except KaitaiStructError as ex:
        raise RawParseError("Unable to parse boot script binary.") from ex


def _generated_module() -> ModuleType:
    try:
        module = import_module(GENERATED_MODULE_NAME)
    except ModuleNotFoundError as ex:
        message = "The generated Kaitai parser or runtime dependency is unavailable."
        raise RawParseError(message) from ex
    return module


def _generated_stream(module: ModuleType, data: bytes) -> Any:
    bytes_io = getattr(module, BYTES_IO_CLASS_NAME)
    kaitai_stream = getattr(module, KAITAI_STREAM_CLASS_NAME)
    return kaitai_stream(bytes_io(data))


def _generated_records(generated_script: object) -> list[object]:
    records = cast(list[object], getattr(generated_script, RECORDS_ATTRIBUTE))
    if not records:
        raise RawParseError("The boot script does not contain a header record.")
    return records


def _read_table_header(generated_records: list[object]) -> RawTableHeader:
    header_record = generated_records[FIRST_RECORD_INDEX]
    _ensure_header_record(header_record)
    return _table_header_from_record(header_record)


def _ensure_header_record(record: object) -> None:
    if _opcode_id(record) != HEADER_OPCODE_ID:
        raise RawParseError("The first boot script record is not a table header.")


def _table_header_from_record(record: object) -> RawTableHeader:
    body = _object_attribute(record, BODY_ATTRIBUTE)
    return RawTableHeader(
        magic=_opcode_id(record),
        length=_record_length(record),
        version=_int_attribute(body, "version"),
        table_length=_int_attribute(body, "table_length"),
    )


def _read_opcode_records(data: bytes, generated_records: list[object]) -> list[RawOpcodeRecord]:
    offsets = _record_offsets(generated_records)
    body_records = zip(
        generated_records[NEXT_RECORD_STEP:],
        offsets[NEXT_RECORD_STEP:],
        strict=True,
    )
    return [_raw_opcode_record(data, record, offset) for record, offset in body_records]


def _record_offsets(generated_records: list[object]) -> list[int]:
    offset = FIRST_OPCODE_OFFSET
    offsets = []
    for record in generated_records:
        offsets.append(offset)
        offset += _record_length(record)
    return offsets


def _raw_opcode_record(data: bytes, generated_record: object, offset: int) -> RawOpcodeRecord:
    length = _record_length(generated_record)
    return RawOpcodeRecord(
        opcode_id=_opcode_id(generated_record),
        length=length,
        offset=offset,
        body=_object_attribute(generated_record, BODY_ATTRIBUTE),
        raw_bytes=data[offset : offset + length],
    )


def _opcode_id(record: object) -> int:
    return _int_attribute(record, OPCODE_ATTRIBUTE)


def _record_length(record: object) -> int:
    return _int_attribute(record, "length")


def _int_attribute(instance: object, name: str) -> int:
    value = _object_attribute(instance, name)
    if isinstance(value, int):
        return value
    return int(cast(SupportsInt, value))


def _object_attribute(instance: object, name: str) -> object:
    return cast(object, getattr(instance, name))
