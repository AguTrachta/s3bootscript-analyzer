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


FieldNames = tuple[str, ...]


@dataclass(frozen=True)
class OpcodeMetadata:
    """Static output metadata for an opcode."""

    opcode_id: int
    mnemonic: str
    fields: FieldNames


class StructuredOpcodeDecoder:
    """Data-driven decoder for opcodes with simple field output."""

    def __init__(self, mnemonic: str, fields: FieldNames) -> None:
        self._mnemonic = mnemonic
        self._fields = fields

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        fields = " ".join(render_field(record.body, field) for field in self._fields)
        return _join_record_text(record, self._mnemonic, fields, verbose)


class IoWriteDecoder(StructuredOpcodeDecoder):
    """Decode IO write records."""

    opcode_id = OpcodeId.IO_WRITE

    def __init__(self) -> None:
        super().__init__("IO_WRITE", WRITE_FIELDS)


class MemWriteDecoder(StructuredOpcodeDecoder):
    """Decode memory write records."""

    opcode_id = OpcodeId.MEM_WRITE

    def __init__(self) -> None:
        super().__init__("MEM_WRITE", WRITE_FIELDS)


class PciConfigWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config write records."""

    opcode_id = OpcodeId.PCI_CONFIG_WRITE

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_WRITE", WRITE_FIELDS)


class PciConfig2WriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 write records."""

    opcode_id = OpcodeId.PCI_CONFIG2_WRITE

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_WRITE", SEGMENTED_WRITE_FIELDS)


class IoReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode IO read-write records."""

    opcode_id = OpcodeId.IO_READ_WRITE

    def __init__(self) -> None:
        super().__init__("IO_READ_WRITE", READ_WRITE_FIELDS)


class MemReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode memory read-write records."""

    opcode_id = OpcodeId.MEM_READ_WRITE

    def __init__(self) -> None:
        super().__init__("MEM_READ_WRITE", READ_WRITE_FIELDS)


class PciConfigReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config read-write records."""

    opcode_id = OpcodeId.PCI_CONFIG_READ_WRITE

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_READ_WRITE", READ_WRITE_FIELDS)


class PciConfig2ReadWriteDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 read-write records."""

    opcode_id = OpcodeId.PCI_CONFIG2_READ_WRITE

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_READ_WRITE", SEGMENTED_READ_WRITE_FIELDS)


class IoPollDecoder(StructuredOpcodeDecoder):
    """Decode IO poll records."""

    opcode_id = OpcodeId.IO_POLL

    def __init__(self) -> None:
        super().__init__("IO_POLL", POLL_FIELDS)


class MemPollDecoder(StructuredOpcodeDecoder):
    """Decode memory poll records."""

    opcode_id = OpcodeId.MEM_POLL

    def __init__(self) -> None:
        super().__init__("MEM_POLL", MEM_POLL_FIELDS)


class PciConfigPollDecoder(StructuredOpcodeDecoder):
    """Decode PCI config poll records."""

    opcode_id = OpcodeId.PCI_CONFIG_POLL

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG_POLL", POLL_FIELDS)


class PciConfig2PollDecoder(StructuredOpcodeDecoder):
    """Decode PCI config 2 poll records."""

    opcode_id = OpcodeId.PCI_CONFIG2_POLL

    def __init__(self) -> None:
        super().__init__("PCI_CONFIG2_POLL", SEGMENTED_POLL_FIELDS)


class SmbusExecuteDecoder(StructuredOpcodeDecoder):
    """Decode SMBus execute records."""

    opcode_id = OpcodeId.SMBUS_EXECUTE

    def __init__(self) -> None:
        super().__init__("SMBUS_EXECUTE", SMBUS_FIELDS)


class StallDecoder(StructuredOpcodeDecoder):
    """Decode stall records."""

    opcode_id = OpcodeId.STALL

    def __init__(self) -> None:
        super().__init__("STALL", STALL_FIELDS)


class DispatchDecoder(StructuredOpcodeDecoder):
    """Decode dispatch records."""

    opcode_id = OpcodeId.DISPATCH

    def __init__(self) -> None:
        super().__init__("DISPATCH", DISPATCH_FIELDS)


class Dispatch2Decoder(StructuredOpcodeDecoder):
    """Decode dispatch 2 records."""

    opcode_id = OpcodeId.DISPATCH_2

    def __init__(self) -> None:
        super().__init__("DISPATCH_2", DISPATCH_2_FIELDS)


class InformationDecoder(StructuredOpcodeDecoder):
    """Decode information records."""

    opcode_id = OpcodeId.INFORMATION

    def __init__(self) -> None:
        super().__init__("INFORMATION", INFORMATION_FIELDS)


class TerminateDecoder(StructuredOpcodeDecoder):
    """Decode terminate records."""

    opcode_id = OpcodeId.TERMINATE

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


def render_field(body: object, name: str) -> str:
    return format_field(name, format_value(_body_field(body, name)))


def _join_record_text(record: RawOpcodeRecord, mnemonic: str, fields: str, verbose: bool) -> str:
    return " ".join(
        part for part in (format_record_prefix(record, mnemonic, verbose), fields) if part
    )


EMPTY_FIELDS: FieldNames = ()
WRITE_FIELDS: FieldNames = ("width", "count", "address", "buffer")
SEGMENTED_WRITE_FIELDS: FieldNames = ("width", "count", "address", "segment", "buffer")
READ_WRITE_FIELDS: FieldNames = ("width", "address", "data", "data_mask")
SEGMENTED_READ_WRITE_FIELDS = (
    "width",
    "address",
    "segment",
    "data",
    "data_mask",
)
POLL_FIELDS: FieldNames = ("width", "address", "delay", "data", "data_mask")
MEM_POLL_FIELDS = (
    "width",
    "address",
    "duration",
    "loop_times",
    "data",
    "data_mask",
)
SEGMENTED_POLL_FIELDS = (
    "width",
    "address",
    "segment",
    "delay",
    "data",
    "data_mask",
)
SMBUS_FIELDS: FieldNames = ("sm_bus_address", "operation", "data_size", "buffer")
STALL_FIELDS: FieldNames = ("duration", )
DISPATCH_FIELDS: FieldNames = ("entry_point", )
DISPATCH_2_FIELDS: FieldNames = ("entry_point", "context")
INFORMATION_FIELDS: FieldNames = ("information_length", "information_data")

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


def get_opcode_fields(opcode_id: int) -> FieldNames:
    metadata = OPCODE_METADATA_BY_ID.get(opcode_id)
    return metadata.fields if metadata is not None else EMPTY_FIELDS
