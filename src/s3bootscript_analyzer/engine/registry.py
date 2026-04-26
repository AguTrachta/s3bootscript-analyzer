"""Opcode decoder registry."""

from __future__ import annotations

from dataclasses import dataclass, field

from s3bootscript_analyzer.engine.decoders import OpcodeDecoder, UnknownOpcodeDecoder
from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord


@dataclass
class OpcodeDecoderRegistry:
    """Resolve and run a decoder for a raw opcode record."""

    _decoders: dict[OpcodeId, OpcodeDecoder] = field(default_factory=dict)
    _unknown_decoder: OpcodeDecoder = field(default_factory=UnknownOpcodeDecoder)

    def register(self, opcode_id: OpcodeId, decoder: OpcodeDecoder) -> None:
        self._decoders[opcode_id] = decoder

    def decode(self, record: RawOpcodeRecord, verbose: bool = False) -> str:
        opcode_id = _known_opcode_id(record.opcode_id)
        if opcode_id is None:
            decoder = self._unknown_decoder.decode(record, verbose)
        decoder = self._decoders.get(opcode_id, self._unknown_decoder)
        return decoder.decode(record, verbose)


def _known_opcode_id(opcode_id: int) -> OpcodeId | None:
    try:
        return OpcodeId(opcode_id)
    except ValueError:
        return None
