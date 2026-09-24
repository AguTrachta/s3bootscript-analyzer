"""Command-line entry point for S3 boot script tools."""

from __future__ import annotations

import argparse
import logging
import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from s3bootscript_analyzer.application import build_default_disassembler
from s3bootscript_analyzer.cli_analysis import (
    EXIT_FAILURE,
    EXIT_SUCCESS,
    build_report_renderer,
    configure_analysis_parser,
    run_analysis,
)
from s3bootscript_analyzer.errors import BootScriptAnalyzerError
from s3bootscript_analyzer.profile_data import (
    GenerateProfile,
    JsonProfileWriter,
    KernelProfileLoader,
    ProcIomemProfileLoader,
    ProfileLoader,
)
from s3bootscript_analyzer.profile_data.commands import SubprocessRunner
from s3bootscript_analyzer.reporting import (
    BootScriptRenderer,
    JsonIrRenderer,
    SemanticIrRenderer,
    TextIrRenderer,
    write_text_output,
)

__all__ = ["EXIT_FAILURE", "EXIT_SUCCESS", "build_parser", "build_report_renderer", "main"]

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
    PROC_IOMEM_KERNEL = "kernel"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3bootscript-analyzer",
        description="Disassemble and analyze UEFI S3 Boot Scripts or generate a platform profile.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--debug",
        action="store_true",
        help="Write diagnostic messages to stderr.",
    )
    report_output = argparse.ArgumentParser(add_help=False)
    report_output.add_argument(
        "-or",
        "--output-report",
        type=Path,
        help="Path where the rendered output should be written.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    disassemble = commands.add_parser(
        "disassemble", parents=[common, report_output], help="Disassemble an S3 Boot Script binary."
    )
    disassemble.add_argument(
        "-i",
        "--input-binary",
        type=Path,
        required=True,
        help="Path to the S3 Boot Script binary to disassemble.",
    )
    disassemble.add_argument(
        "-of",
        "--output-format",
        type=OutputFormat,
        choices=tuple(OutputFormat),
        default=OutputFormat.TEXT,
        help="Output format to render.",
    )
    disassemble.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Include opcode, length, and payload metadata in text output.",
    )
    _configure_profile_parser(
        commands.add_parser(
            "generate-profile", parents=[common], help="Generate a platform profile."
        )
    )
    analyze = commands.add_parser(
        "analyze", parents=[common, report_output], help="Analyze binary using rules."
    )
    configure_analysis_parser(analyze)
    analyze.set_defaults(command_parser=analyze)
    return parser


def _configure_profile_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source",
        type=ProfileGenerationSource,
        choices=tuple(ProfileGenerationSource),
        required=True,
        help="Generate a platform profile from the selected source.",
    )
    parser.add_argument(
        "--profile-output",
        type=Path,
        help="Path where the generated platform profile JSON should be written.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate_analysis_verbosity(args)
    _configure_logging(args.debug)
    if args.command == "analyze":
        return run_analysis(args, build_report_renderer)
    if args.command == "generate-profile":
        return _generate_profile(args.source, args.profile_output)
    return _run(args)


def _validate_analysis_verbosity(args: argparse.Namespace) -> None:
    if args.command == "analyze" and args.debug and args.quiet:
        args.command_parser.error("--quiet: not allowed with argument --debug")


def _run(args: argparse.Namespace) -> int:
    return _disassemble(
        args.input_binary,
        args.output_report,
        _build_renderer(args.output_format, args.verbose),
        args.verbose,
    )


def _generate_profile(source: ProfileGenerationSource, profile_output: Path | None) -> int:
    if source == ProfileGenerationSource.PROC_IOMEM:
        return _generate_proc_iomem_profile(profile_output)
    return _generate_kernel_iomem_profile(profile_output)


def _generate_proc_iomem_profile(
    profile_output: Path | None,
) -> int:
    writer = JsonProfileWriter()
    loader = ProcIomemProfileLoader(SubprocessRunner())
    try:
        _write_generated_profile(loader, writer, profile_output)
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


def _generate_kernel_iomem_profile(
    profile_output: Path | None,
) -> int:
    writer = JsonProfileWriter()
    loader = KernelProfileLoader(SubprocessRunner())
    try:
        _write_generated_profile(loader, writer, profile_output)
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


def _write_generated_profile(
    loader: ProfileLoader,
    writer: JsonProfileWriter,
    profile_output: Path | None,
) -> None:
    if profile_output is None:
        print(writer.render(loader.load()), end="")
        return
    GenerateProfile(output_path=profile_output, loader=loader, writer=writer).run()


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
