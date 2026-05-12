"""Application layer for boot script disassembly."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from s3bootscript_analyzer.engine import BootScriptOpcodeDecoder, build_default_opcode_decoder
from s3bootscript_analyzer.ingest import FileLoader
from s3bootscript_analyzer.parsers import BootScriptRawParser, KaitaiBootScriptRawParser
from s3bootscript_analyzer.reporting import BootScriptRenderer, TextIrRenderer

APPLICATION_NAME: Final[str] = "s3bootscript-analyzer"
APPLICATION_STATUS_READY: Final[str] = "ready"
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApplicationInfo:
    """Static metadata exposed for integration checks."""

    name: str = APPLICATION_NAME
    status: str = APPLICATION_STATUS_READY


@dataclass(frozen=True)
class BootScriptDisassembler:
    """Coordinate loading, parsing, decoding, and text rendering."""

    file_loader: FileLoader
    raw_parser: BootScriptRawParser
    opcode_decoder: BootScriptOpcodeDecoder
    renderer: BootScriptRenderer
    verbose: bool = False

    def execute(self, path: str | Path) -> str:
        _LOGGER.debug("starting disassembly path=%s", path)
        raw_script = self.raw_parser.parse(self.file_loader.load(path))
        _LOGGER.debug(
            "parsed boot script magic=0x%x header_length=%d "
            "version=0x%x table_length=%d records=%d",
            raw_script.table_header.magic,
            raw_script.table_header.length,
            raw_script.table_header.version,
            raw_script.table_header.table_length,
            len(raw_script.records),
        )
        header_text = self.opcode_decoder.decode_header(raw_script.table_header)
        opcode_lines = self.opcode_decoder.decode_all(raw_script, self.verbose)
        _LOGGER.debug("decoded opcode records count=%d", len(opcode_lines))
        output = self.renderer.render(raw_script, header_text, opcode_lines)
        _LOGGER.debug("rendered output length=%d", len(output))
        return output


def get_application_info() -> ApplicationInfo:
    """Return package metadata."""

    return ApplicationInfo()


def build_default_disassembler(
    renderer: BootScriptRenderer | None = None, verbose: bool = False
) -> BootScriptDisassembler:
    """Build the default disassembler from concrete adapters."""

    return BootScriptDisassembler(
        file_loader=FileLoader(),
        raw_parser=KaitaiBootScriptRawParser(),
        opcode_decoder=build_default_opcode_decoder(),
        renderer=renderer or TextIrRenderer(),
        verbose=verbose,
    )
