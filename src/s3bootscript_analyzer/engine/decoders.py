"""Concrete opcode decoders."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from s3bootscript_analyzer.engine.formatting import (
    MISSING_FIELD,
    format_bytes,
    format_field,
    format_record_prefix,
    format_value,
)
from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord


class OpcodeDecoder(Protocol):
    """Decode one raw opcode into textual IR."""

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        """Decode a raw opcode record."""
        raise NotImplementedError


@dataclass(frozen=True)
class FieldSpec:
    """A field read from a generated Kaitai body."""

    name: str

    def render(self, body: object) -> str:
        return format_field(self.name, self.format_value(body))

    def format_value(self, body: object) -> str:
        return format_value(_body_field(body, self.name))


@dataclass(frozen=True)
class OpcodeMetadata:
    """Static output metadata for an opcode."""

    opcode_id: int
    mnemonic: str
    fields: tuple[FieldSpec, ...]


class StructuredOpcodeDecoder:
    """Data-driven decoder for opcodes with simple field output."""

    def __init__(self, mnemonic: str, fields: tuple[FieldSpec, ...]) -> None:
        self._mnemonic = mnemonic
        self._fields = fields

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        fields = " ".join(field.render(record.body) for field in self._fields)
        return _join_record_text(record, self._mnemonic, fields, verbose)


class IoWriteDecoder(StructuredOpcodeDecoder):
    """Decode IO write records."""

    def __init__(self) -> None:
        super().__init__("IO_WRITE", WRITE_FIELDS)


class MemWriteDecoder(StructuredOpcodeDecoder):
    """Decode memory write records."""

    def __init__(self) -> None:
        super().__init__("MEM_WRITE", WRITE_FIELDS)


class PciConfigWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config write records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_WRITE", WRITE_FIELDS)


class PciConfig2WriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 write records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_WRITE", SEGMENTED_WRITE_FIELDS)


class IoReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode IO read-write records."""

    def __init__(self) -> None:
        super().__init__("IO_READ_WRITE", READ_WRITE_FIELDS)


class MemReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode memory read-write records."""

    def __init__(self) -> None:
        super().__init__("MEM_READ_WRITE", READ_WRITE_FIELDS)


class PciConfigReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config read-write records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_READ_WRITE", READ_WRITE_FIELDS)


class PciConfig2ReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 read-write records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_READ_WRITE", SEGMENTED_READ_WRITE_FIELDS)


class IoPollDecoder(StructuredOpcodeDecoder):
    """Decode IO poll records."""

    def __init__(self) -> None:
        super().__init__("IO_POLL", POLL_FIELDS)


class MemPollDecoder(StructuredOpcodeDecoder):
    """Decode memory poll records."""

    def __init__(self) -> None:
        super().__init__("MEM_POLL", MEM_POLL_FIELDS)


class PciConfigPollDecoder(StructuredOpcodeDecoder):
    """Decode PCI config poll records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_POLL", POLL_FIELDS)


class PciConfig2PollDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 poll records."""

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_POLL", SEGMENTED_POLL_FIELDS)


class SmbusExecuteDecoder(StructuredOpcodeDecoder):
    """Decode SMBus execute records."""

    def __init__(self) -> None:
        super().__init__("SMBUS_EXECUTE", SMBUS_FIELDS)


class StallDecoder(StructuredOpcodeDecoder):
    """Decode stall records."""

    def __init__(self) -> None:
        super().__init__("STALL", STALL_FIELDS)


class DispatchDecoder(StructuredOpcodeDecoder):
    """Decode dispatch records."""

    def __init__(self) -> None:
        super().__init__("DISPATCH", DISPATCH_FIELDS)


class Dispatch2Decoder(StructuredOpcodeDecoder):
    """Decode dispatch 2 records."""

    def __init__(self) -> None:
        super().__init__("DISPATCH_2", DISPATCH_2_FIELDS)


class InformationDecoder(StructuredOpcodeDecoder):
    """Decode information records."""

    def __init__(self) -> None:
        super().__init__("INFORMATION", INFORMATION_FIELDS)


class TerminateDecoder(StructuredOpcodeDecoder):
    """Decode terminate records."""

    def __init__(self) -> None:
        super().__init__("TERMINATE", EMPTY_FIELDS)


class UnknownOpcodeDecoder:
    """Fallback decoder for unsupported or malformed opcodes."""

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        return _join_record_text(
            record,
            UNKNOWN_MNEMONIC,
            f"raw={format_bytes(record.raw_bytes)}",
            verbose,
        )


def _body_field(body: object, name: str) -> object:
    return cast(object, getattr(body, name, MISSING_FIELD))


def _join_record_text(record: RawOpcodeRecord, mnemonic: str, fields: str, verbose: bool) -> str:
    return " ".join(
        part for part in (format_record_prefix(record, mnemonic, verbose), fields) if part
    )


FIELD_WIDTH = FieldSpec("width")
FIELD_COUNT = FieldSpec("count")
FIELD_ADDRESS = FieldSpec("address")
FIELD_SEGMENT = FieldSpec("segment")
FIELD_BUFFER = FieldSpec("buffer")
FIELD_DATA = FieldSpec("data")
FIELD_DATA_MASK = FieldSpec("data_mask")
FIELD_DELAY = FieldSpec("delay")
FIELD_DURATION = FieldSpec("duration")
FIELD_LOOP_TIMES = FieldSpec("loop_times")
FIELD_ENTRY_POINT = FieldSpec("entry_point")
FIELD_CONTEXT = FieldSpec("context")
FIELD_INFORMATION_LENGTH = FieldSpec("information_length")
FIELD_INFORMATION_DATA = FieldSpec("information_data")
FIELD_SM_BUS_ADDRESS = FieldSpec("sm_bus_address")
FIELD_OPERATION = FieldSpec("operation")
FIELD_DATA_SIZE = FieldSpec("data_size")

EMPTY_FIELDS: tuple[FieldSpec, ...] = ()
WRITE_FIELDS = (FIELD_WIDTH, FIELD_COUNT, FIELD_ADDRESS, FIELD_BUFFER)
SEGMENTED_WRITE_FIELDS = (FIELD_WIDTH, FIELD_COUNT, FIELD_ADDRESS, FIELD_SEGMENT, FIELD_BUFFER)
READ_WRITE_FIELDS = (FIELD_WIDTH, FIELD_ADDRESS, FIELD_DATA, FIELD_DATA_MASK)
SEGMENTED_READ_WRITE_FIELDS = (
    FIELD_WIDTH,
    FIELD_ADDRESS,
    FIELD_SEGMENT,
    FIELD_DATA,
    FIELD_DATA_MASK,
)
POLL_FIELDS = (FIELD_WIDTH, FIELD_ADDRESS, FIELD_DELAY, FIELD_DATA, FIELD_DATA_MASK)
MEM_POLL_FIELDS = (
    FIELD_WIDTH,
    FIELD_ADDRESS,
    FIELD_DURATION,
    FIELD_LOOP_TIMES,
    FIELD_DATA,
    FIELD_DATA_MASK,
)
SEGMENTED_POLL_FIELDS = (
    FIELD_WIDTH,
    FIELD_ADDRESS,
    FIELD_SEGMENT,
    FIELD_DELAY,
    FIELD_DATA,
    FIELD_DATA_MASK,
)
SMBUS_FIELDS = (FIELD_SM_BUS_ADDRESS, FIELD_OPERATION, FIELD_DATA_SIZE, FIELD_BUFFER)
STALL_FIELDS = (FIELD_DURATION, )
DISPATCH_FIELDS = (FIELD_ENTRY_POINT, )
DISPATCH_2_FIELDS = (FIELD_ENTRY_POINT, FIELD_CONTEXT)
INFORMATION_FIELDS = (FIELD_INFORMATION_LENGTH, FIELD_INFORMATION_DATA)

UNKNOWN_MNEMONIC = "UNKNOWN"

OPCODE_METADATA: tuple[OpcodeMetadata, ...] = (
    OpcodeMetadata(OpcodeId.IO_WRITE, "IO_WRITE", WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.IO_READ_WRITE, "IO_READ_WRITE", READ_WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.MEM_WRITE, "MEM_WRITE", WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.MEM_READ_WRITE, "MEM_READ_WRITE", READ_WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.PCI_CONFIG_WRITE, "PCI_CONFIG_WRITE", WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.PCI_CONFIG_READ_WRITE, "PCI_CONFIG_READ_WRITE", READ_WRITE_FIELDS),
    OpcodeMetadata(OpcodeId.SMBUS_EXECUTE, "SMBUS_EXECUTE", SMBUS_FIELDS),
    OpcodeMetadata(OpcodeId.STALL, "STALL", STALL_FIELDS),
    OpcodeMetadata(OpcodeId.DISPATCH, "DISPATCH", DISPATCH_FIELDS),
    OpcodeMetadata(OpcodeId.DISPATCH_2, "DISPATCH_2", DISPATCH_2_FIELDS),
    OpcodeMetadata(OpcodeId.INFORMATION, "INFORMATION", INFORMATION_FIELDS),
    OpcodeMetadata(OpcodeId.PCI_CONFIG2_WRITE, "PCI_CONFIG2_WRITE", SEGMENTED_WRITE_FIELDS),
    OpcodeMetadata(
        OpcodeId.PCI_CONFIG2_READ_WRITE,
        "PCI_CONFIG2_READ_WRITE",
        SEGMENTED_READ_WRITE_FIELDS,
    ),
    OpcodeMetadata(OpcodeId.IO_POLL, "IO_POLL", POLL_FIELDS),
    OpcodeMetadata(OpcodeId.MEM_POLL, "MEM_POLL", MEM_POLL_FIELDS),
    OpcodeMetadata(OpcodeId.PCI_CONFIG_POLL, "PCI_CONFIG_POLL", POLL_FIELDS),
    OpcodeMetadata(OpcodeId.PCI_CONFIG2_POLL, "PCI_CONFIG2_POLL", SEGMENTED_POLL_FIELDS),
    OpcodeMetadata(OpcodeId.TERMINATE, "TERMINATE", EMPTY_FIELDS),
)
OPCODE_METADATA_BY_ID = {metadata.opcode_id: metadata for metadata in OPCODE_METADATA}


def get_opcode_mnemonic(opcode_id: int) -> str:
    metadata = OPCODE_METADATA_BY_ID.get(opcode_id)
    return metadata.mnemonic if metadata is not None else UNKNOWN_MNEMONIC


def get_opcode_fields(opcode_id: int) -> tuple[FieldSpec, ...]:
    metadata = OPCODE_METADATA_BY_ID.get(opcode_id)
    return metadata.fields if metadata is not None else EMPTY_FIELDS
