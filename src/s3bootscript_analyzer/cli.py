"""Command-line entry point for S3 boot script disassembly."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from s3bootscript_analyzer.application import build_default_use_case
from s3bootscript_analyzer.errors import BootScriptAnalyzerError
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


class OutputFormat(StrEnum):
    """Supported report output formats."""

    TEXT = "text"
    JSON = "json"
    SEMANTIC = "semantic"


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _run(args)


def _run(args: argparse.Namespace) -> int:
    if args.input_binary is None:
        print(READY_MESSAGE)
        return EXIT_SUCCESS
    return _disassemble(
        args.input_binary,
        args.output_report,
        _build_renderer(args.output_format, args.verbose),
        args.verbose,
    )


def _disassemble(
    input_binary: Path,
    output_report: Path | None,
    renderer: BootScriptRenderer,
    verbose: bool,
) -> int:
    try:
        output = build_default_use_case(renderer, verbose=verbose).execute(input_binary)
        write_text_output(output, output_report)
    except BootScriptAnalyzerError as ex:
        print(f"Error: {ex}")
        return EXIT_FAILURE
    return EXIT_SUCCESS


def _build_renderer(output_format: OutputFormat, verbose: bool) -> BootScriptRenderer:
    if output_format == OutputFormat.JSON:
        return JsonIrRenderer()
    if output_format == OutputFormat.SEMANTIC:
        return SemanticIrRenderer()
    return TextIrRenderer(verbose=verbose)


if __name__ == "__main__":
    raise SystemExit(main())
