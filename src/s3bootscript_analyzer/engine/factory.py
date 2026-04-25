"""Factories for default decoder wiring."""

from __future__ import annotations

from typing import Protocol

from s3bootscript_analyzer.engine.decoders import (
    Dispatch2Decoder,
    DispatchDecoder,
    InformationDecoder,
    IoPollDecoder,
    IoReadWriteDecoder,
    IoWriteDecoder,
    MemPollDecoder,
    MemReadWriteDecoder,
    MemWriteDecoder,
    OpcodeDecoder,
    PciConfig2PollDecoder,
    PciConfig2ReadWriteDecoder,
    PciConfig2WriteDecoder,
    PciConfigPollDecoder,
    PciConfigReadWriteDecoder,
    PciConfigWriteDecoder,
    SmbusExecuteDecoder,
    StallDecoder,
    TerminateDecoder,
)
from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.engine.registry import OpcodeDecoderRegistry
from s3bootscript_analyzer.engine.script_decoder import BootScriptOpcodeDecoder


class DecoderFactory(Protocol):
    opcode_id: OpcodeId

    def __call__(self) -> OpcodeDecoder:
        raise NotImplementedError


DEFAULT_DECODER_FACTORIES: tuple[DecoderFactory, ...] = (
    IoWriteDecoder,
    IoReadWriteDecoder,
    MemWriteDecoder,
    MemReadWriteDecoder,
    PciConfigWriteDecoder,
    PciConfigReadWriteDecoder,
    SmbusExecuteDecoder,
    StallDecoder,
    DispatchDecoder,
    Dispatch2Decoder,
    InformationDecoder,
    PciConfig2WriteDecoder,
    PciConfig2ReadWriteDecoder,
    IoPollDecoder,
    MemPollDecoder,
    PciConfigPollDecoder,
    PciConfig2PollDecoder,
    TerminateDecoder,
)


def build_default_registry() -> OpcodeDecoderRegistry:
    registry = OpcodeDecoderRegistry()
    for decoder_factory in DEFAULT_DECODER_FACTORIES:
        registry.register(decoder_factory.opcode_id, decoder_factory())
    return registry


def build_default_opcode_decoder() -> BootScriptOpcodeDecoder:
    return BootScriptOpcodeDecoder(registry=build_default_registry())
