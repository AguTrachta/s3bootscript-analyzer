"""Opcode decoder registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from s3bootscript_analyzer.engine.decoders import OpcodeDecoder, UnknownOpcodeDecoder
from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord


@dataclass
class OpcodeDecoderRegistry:
    """Resolve and run a decoder for a raw opcode record."""

    _decoders: dict[int, OpcodeDecoder] = field(default_factory=dict)
    _unknown_decoder: OpcodeDecoder = field(default_factory=UnknownOpcodeDecoder)

    def register(self, opcode_id: int, decoder: OpcodeDecoder) -> None:
        self._decoders[opcode_id] = decoder

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        decoder = self._decoders.get(record.opcode_id, self._unknown_decoder)
        return decoder.decode(record, verbose)
