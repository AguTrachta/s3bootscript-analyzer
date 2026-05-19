"""Command-line entry point for S3 boot script disassembly."""

from __future__ import annotations

import argparse
import logging
import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from s3bootscript_analyzer.application import build_default_disassembler
from s3bootscript_analyzer.errors import BootScriptAnalyzerError
from s3bootscript_analyzer.profile_data import (
    JsonProfileWriter,
    ProcIomemParser,
    ProcIomemReader,
)
from s3bootscript_analyzer.profile_data.commands import SubprocessRunner
from s3bootscript_analyzer.reporting import (
    BootScriptRenderer,
    JsonIrRenderer,
    SemanticIrRenderer,
    TextIrRenderer,
    write_text_output,
)

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
READY_MESSAGE = "s3bootscript-analyzer scaffold ready."
DEBUG_LOG_FORMAT = "Debug: %(message)s"
_LOGGER = logging.getLogger(__name__)


class OutputFormat(StrEnum):
    """Supported report output formats."""

    TEXT = "text"
    JSON = "json"
    SEMANTIC = "semantic"


class ProfileGenerationSource(StrEnum):
    """Supported platform profile generation sources."""

    PROC_IOMEM = "proc-iomem"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3bootscript-analyzer",
        description="Disassemble UEFI S3 Boot Script binaries.",
    )
    parser.add_argument(
        "-i",
        "--input-binary",
        type=Path,
        help="Path to the S3 Boot Script binary to disassemble.",
    )
    parser.add_argument(
        "-or",
        "--output-report",
        type=Path,
        help="Path where the rendered output should be written.",
    )
    parser.add_argument(
        "-of",
        "--output-format",
        type=OutputFormat,
        choices=tuple(OutputFormat),
        default=OutputFormat.TEXT,
        help="Output format to render.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Include opcode, length, and payload metadata in text output.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Write diagnostic messages to stderr while disassembling.",
    )
    parser.add_argument(
        "--generate-profile",
        type=ProfileGenerationSource,
        choices=tuple(ProfileGenerationSource),
        help="Generate a platform profile from the selected source.",
    )
    parser.add_argument(
        "--profile-output",
        type=Path,
        help="Path where the generated platform profile JSON should be written.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.debug)
    return _run(args)


def _run(args: argparse.Namespace) -> int:
    if args.generate_profile == ProfileGenerationSource.PROC_IOMEM:
        return _generate_proc_iomem_profile(args.profile_output)
    if args.input_binary is None:
        print(READY_MESSAGE)
        return EXIT_SUCCESS
    return _disassemble(
        args.input_binary,
        args.output_report,
        _build_renderer(args.output_format, args.verbose),
        args.verbose,
    )


def _generate_proc_iomem_profile(
    profile_output: Path | None,
) -> int:
    writer = JsonProfileWriter()
    try:
        profile = ProcIomemParser().parse(ProcIomemReader(SubprocessRunner()).read())
        if profile_output is None:
            print(writer.render(profile), end="")
        else:
            writer.write(profile, profile_output)
    except BootScriptAnalyzerError as ex:
        _log_analyzer_error(ex)
        print(f"Error: {ex}")
        return EXIT_FAILURE
    except subprocess.CalledProcessError as ex:
        _LOGGER.debug(
            "profile source command failed returncode=%d command=%s",
            ex.returncode,
            ex.cmd,
        )
        print(
            f"Error: unable to read profile source: command failed with exit code {ex.returncode}"
        )
        return EXIT_FAILURE
    return EXIT_SUCCESS


def _disassemble(
    input_binary: Path,
    output_report: Path | None,
    renderer: BootScriptRenderer,
    verbose: bool,
) -> int:
    try:
        output = build_default_disassembler(renderer, verbose=verbose).execute(input_binary)
        write_text_output(output, output_report)
    except BootScriptAnalyzerError as ex:
        _log_analyzer_error(ex)
        print(f"Error: {ex}")
        return EXIT_FAILURE
    return EXIT_SUCCESS


def _build_renderer(output_format: OutputFormat, verbose: bool) -> BootScriptRenderer:
    if output_format == OutputFormat.JSON:
        return JsonIrRenderer()
    if output_format == OutputFormat.SEMANTIC:
        return SemanticIrRenderer()
    return TextIrRenderer(verbose=verbose)


def _configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format=DEBUG_LOG_FORMAT, stream=sys.stderr, force=True)
    if debug:
        _LOGGER.debug("debug logging enabled")


def _log_analyzer_error(error: BootScriptAnalyzerError) -> None:
    _LOGGER.debug(
        "analyzer error type=%s message=%s",
        error.__class__.__name__,
        error,
    )
    if error.__cause__ is None:
        return
    _LOGGER.debug(
        "analyzer error cause type=%s message=%s",
        error.__cause__.__class__.__name__,
        error.__cause__,
    )


if __name__ == "__main__":
    raise SystemExit(main())
