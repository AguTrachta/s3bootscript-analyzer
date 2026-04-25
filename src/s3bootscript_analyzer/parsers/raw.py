"""Raw parser contracts and domain records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from s3bootscript_analyzer.ingest.source import BinarySource


@dataclass(frozen=True)
class RawTableHeader:
    """Raw boot script table header extracted from the header opcode."""

    magic: int
    length: int
    version: int
    table_length: int


@dataclass(frozen=True)
class RawOpcodeRecord:
    """Raw opcode record plus parser metadata."""

    opcode_id: int
    length: int
    offset: int
    body: object
    raw_bytes: bytes

    def payload_size(self) -> int:
        """Return the serialized body size in bytes."""

        return max(len(self.raw_bytes) - RECORD_PREFIX_SIZE, EMPTY_PAYLOAD_SIZE)


@dataclass(frozen=True)
class RawBootScript:
    """Parsed boot script represented as raw opcode records."""

    table_header: RawTableHeader
    records: list[RawOpcodeRecord]


class BootScriptRawParser(Protocol):
    """Parser contract used by the application layer."""

    def parse(self, source: BinarySource) -> RawBootScript:
        """Parse a binary source into a raw boot script."""
        raise NotImplementedError


RECORD_OPCODE_SIZE = 2
RECORD_LENGTH_SIZE = 1
RECORD_PREFIX_SIZE = RECORD_OPCODE_SIZE + RECORD_LENGTH_SIZE
EMPTY_PAYLOAD_SIZE = 0
