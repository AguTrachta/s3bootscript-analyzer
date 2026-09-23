"""Analysis command arguments, adapter composition, and process results."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisReport,
    AnalysisRequest,
    AnalysisSetupError,
    AnalyzeArtifact,
    Diagnostic,
    EvaluationOutcome,
    ProfileSelection,
    ReportRenderer,
    SimpleEvalConditionEvaluator,
)
from s3bootscript_analyzer.errors import BootScriptAnalyzerError
from s3bootscript_analyzer.extensions import PluginCatalog
from s3bootscript_analyzer.ingest import FileLoader
from s3bootscript_analyzer.ir import SemanticIrBuilder
from s3bootscript_analyzer.matchers import AstGrepMatcher
from s3bootscript_analyzer.parsers import KaitaiBootScriptRawParser
from s3bootscript_analyzer.plugins import S3BootScriptPlugin
from s3bootscript_analyzer.profile_data import JsonProfileLoader
from s3bootscript_analyzer.reporting import write_text_output
from s3bootscript_analyzer.reporting.analysis_report import JinjaReportRenderer
from s3bootscript_analyzer.rules import RuleSource, YamlRuleLoader

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_MATCHED = 3
GRAMMAR_CONFIG = Path(__file__).resolve().parents[2] / "tools" / "semantic_ir" / "sgconfig.yml"


def configure_analysis_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-i", "--input-binary", type=Path, required=True, help="S3 Boot Script binary to analyze."
    )
    parser.add_argument(
        "--rule", type=Path, action="append", required=True, help="Rule YAML path; repeat in order."
    )
    parser.add_argument("--profile", type=Path, help="Profile JSON path; defaults to empty facts.")
    parser.add_argument(
        "-of",
        "--output-format",
        choices=("markdown", "html"),
        default="markdown",
        help="Report format; defaults to markdown.",
    )
    parser.add_argument("--quiet", action="store_true")


def build_report_renderer(output_format: str) -> ReportRenderer:
    """Select the report adapter for the requested format."""
    return JinjaReportRenderer(output_format)


def run_analysis(
    args: argparse.Namespace, renderer_factory: Callable[[str], ReportRenderer]
) -> int:
    try:
        renderer = renderer_factory(args.output_format)
        report = _build_analysis().execute(_request(args))
        _write_diagnostics(report.diagnostics)
        _write_diagnostics(_evaluation_errors(report))
        write_text_output(renderer.render(report), args.output_report)
    except (AnalysisSetupError, BootScriptAnalyzerError, OSError, UnicodeError) as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return EXIT_FAILURE
    return _exit_status(report)


def _build_analysis() -> AnalyzeArtifact:
    matcher = AstGrepMatcher(executable=Path("ast-grep"), config_path=GRAMMAR_CONFIG)
    plugin = S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder(), [matcher])
    return AnalyzeArtifact(
        plugins=PluginCatalog([plugin]),
        rules=YamlRuleLoader(),
        profiles=JsonProfileLoader(),
        engine=AnalysisEngine(SimpleEvalConditionEvaluator()),
    )


def _request(args: argparse.Namespace) -> AnalysisRequest:
    return AnalysisRequest(
        artifact=FileLoader().load(args.input_binary),
        plugin_id=S3BootScriptPlugin.plugin_id,
        rule_sources=tuple(_read_rule(path) for path in args.rule),
        profile_selection=ProfileSelection(args.profile),
    )


def _read_rule(path: Path) -> RuleSource:
    try:
        return RuleSource(str(path), path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as ex:
        raise AnalysisSetupError(f"Unable to read rule '{path}': {ex}") from ex


def _evaluation_errors(report: AnalysisReport) -> Iterable[Diagnostic]:
    return (
        diagnostic
        for evaluation in report.evaluations
        if evaluation.outcome is EvaluationOutcome.ERROR
        for diagnostic in evaluation.diagnostics
    )


def _write_diagnostics(diagnostics: Iterable[Diagnostic]) -> None:
    for diagnostic in diagnostics:
        print(f"Error: {diagnostic.source}: {diagnostic.message}", file=sys.stderr)


def _exit_status(report: AnalysisReport) -> int:
    if _has_errors(report):
        return EXIT_FAILURE
    matched = any(item.outcome is EvaluationOutcome.MATCHED for item in report.evaluations)
    return EXIT_MATCHED if matched else EXIT_SUCCESS


def _has_errors(report: AnalysisReport) -> bool:
    return bool(report.diagnostics) or any(
        item.outcome is EvaluationOutcome.ERROR for item in report.evaluations
    )
