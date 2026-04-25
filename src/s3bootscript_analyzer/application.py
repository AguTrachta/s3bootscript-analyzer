"""Application layer for boot script disassembly."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from s3bootscript_analyzer.engine import BootScriptOpcodeDecoder, build_default_opcode_decoder
from s3bootscript_analyzer.ingest import FileLoader
from s3bootscript_analyzer.parsers import BootScriptRawParser, KaitaiBootScriptRawParser
from s3bootscript_analyzer.reporting import BootScriptRenderer, TextIrRenderer


class ApplicationName(StrEnum):
    """Known application identifiers."""

    S3_BOOTSCRIPT_ANALYZER = "s3bootscript-analyzer"


class ApplicationStatus(StrEnum):
    """Known application readiness states."""

    READY = "ready"


@dataclass(frozen=True)
class ApplicationInfo:
    """Static metadata exposed for integration checks."""

    name: ApplicationName = ApplicationName.S3_BOOTSCRIPT_ANALYZER
    status: ApplicationStatus = ApplicationStatus.READY


@dataclass(frozen=True)
class DisassembleBootScriptUseCase:
    """Coordinate loading, parsing, decoding, and text rendering."""

    file_loader: FileLoader
    raw_parser: BootScriptRawParser
    opcode_decoder: BootScriptOpcodeDecoder
    renderer: BootScriptRenderer
    verbose: bool = False

    def execute(self, path: str | Path) -> str:
        source = self.file_loader.load(path)
        raw_script = self.raw_parser.parse(source)
        header_text = self.opcode_decoder.decode_header(raw_script.table_header)
        opcode_lines = self.opcode_decoder.decode_all(raw_script, self.verbose)
        return self.renderer.render(raw_script, header_text, opcode_lines)


def get_application_info() -> ApplicationInfo:
    """Return package metadata."""

    return ApplicationInfo()


def build_default_use_case(
    renderer: BootScriptRenderer | None = None,
    verbose: bool = False
) -> DisassembleBootScriptUseCase:
    """Build the default disassembly use case from concrete adapters."""

    return DisassembleBootScriptUseCase(
        file_loader=FileLoader(),
        raw_parser=KaitaiBootScriptRawParser(),
        opcode_decoder=build_default_opcode_decoder(),
        renderer=renderer or TextIrRenderer(),
        verbose=verbose,
    )
