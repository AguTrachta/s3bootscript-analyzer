"""Opcode decoder registry."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from s3bootscript_analyzer.engine.decoders import OpcodeDecoder, UnknownOpcodeDecoder
from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.parsers.raw import RawOpcodeRecord

_LOGGER = logging.getLogger(__name__)


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
            _log_unknown_opcode(record)
            return self._unknown_decoder.decode(record, verbose)
        decoder = self._decoders.get(opcode_id, self._unknown_decoder)
        if decoder is self._unknown_decoder:
            _log_unknown_opcode(record)
        return decoder.decode(record, verbose)


def _known_opcode_id(opcode_id: int) -> OpcodeId | None:
    try:
        return OpcodeId(opcode_id)
    except ValueError:
        return None


def _log_unknown_opcode(record: RawOpcodeRecord) -> None:
    _LOGGER.debug(
        "unknown opcode fallback offset=0x%x opcode=0x%x length=%d",
        record.offset,
        record.opcode_id,
        record.length,
    )
