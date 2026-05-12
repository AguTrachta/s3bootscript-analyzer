"""Boot script decoding components."""

from __future__ import annotations

from s3bootscript_analyzer.engine.factory import build_default_opcode_decoder
from s3bootscript_analyzer.engine.registry import OpcodeDecoderRegistry
from s3bootscript_analyzer.engine.script_decoder import BootScriptOpcodeDecoder

__all__ = [
    "BootScriptOpcodeDecoder",
    "OpcodeDecoderRegistry",
    "build_default_opcode_decoder",
]
