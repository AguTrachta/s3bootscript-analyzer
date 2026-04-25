"""Whole-script opcode decoding coordinator."""

from __future__ import annotations

from dataclasses import dataclass

from s3bootscript_analyzer.engine.formatting import format_integer
from s3bootscript_analyzer.engine.registry import OpcodeDecoderRegistry
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawTableHeader

HEADER_MNEMONIC = "BOOT_SCRIPT_TABLE"


@dataclass(frozen=True)
class BootScriptOpcodeDecoder:
    """Decode headers and records into textual IR lines."""

    registry: OpcodeDecoderRegistry

    def decode_header(self, header: RawTableHeader) -> str:
        return (
            f"{HEADER_MNEMONIC} magic={format_integer(header.magic)} "
            f"length={header.length} version={format_integer(header.version)} "
            f"table_length={header.table_length}"
        )

    def decode_all(self, raw_script: RawBootScript, verbose: bool = False) -> list[str]:
        return [self.registry.decode(record, verbose) for record in raw_script.records]
