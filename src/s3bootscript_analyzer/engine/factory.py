"""Factories for default decoder wiring."""

from __future__ import annotations

from collections.abc import Callable

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

DecoderFactory = Callable[[], OpcodeDecoder]

DEFAULT_DECODER_FACTORIES: tuple[tuple[OpcodeId, DecoderFactory], ...] = (
    (OpcodeId.IO_WRITE, IoWriteDecoder),
    (OpcodeId.IO_READ_WRITE, IoReadWriteDecoder),
    (OpcodeId.MEM_WRITE, MemWriteDecoder),
    (OpcodeId.MEM_READ_WRITE, MemReadWriteDecoder),
    (OpcodeId.PCI_CONFIG_WRITE, PciConfigWriteDecoder),
    (OpcodeId.PCI_CONFIG_READ_WRITE, PciConfigReadWriteDecoder),
    (OpcodeId.SMBUS_EXECUTE, SmbusExecuteDecoder),
    (OpcodeId.STALL, StallDecoder),
    (OpcodeId.DISPATCH, DispatchDecoder),
    (OpcodeId.DISPATCH_2, Dispatch2Decoder),
    (OpcodeId.INFORMATION, InformationDecoder),
    (OpcodeId.PCI_CONFIG2_WRITE, PciConfig2WriteDecoder),
    (OpcodeId.PCI_CONFIG2_READ_WRITE, PciConfig2ReadWriteDecoder),
    (OpcodeId.IO_POLL, IoPollDecoder),
    (OpcodeId.MEM_POLL, MemPollDecoder),
    (OpcodeId.PCI_CONFIG_POLL, PciConfigPollDecoder),
    (OpcodeId.PCI_CONFIG2_POLL, PciConfig2PollDecoder),
    (OpcodeId.TERMINATE, TerminateDecoder),
)


def build_default_registry() -> OpcodeDecoderRegistry:
    registry = OpcodeDecoderRegistry()
    for opcode_id, decoder_factory in DEFAULT_DECODER_FACTORIES:
        registry.register(int(opcode_id), decoder_factory())
    return registry


def build_default_opcode_decoder() -> BootScriptOpcodeDecoder:
    return BootScriptOpcodeDecoder(registry=build_default_registry())
