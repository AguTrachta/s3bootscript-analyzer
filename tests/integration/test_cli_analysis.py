"""Analysis CLI composition stories; report templates are a separate boundary."""

import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from s3bootscript_analyzer import cli
from s3bootscript_analyzer.analysis import AnalysisReport, EvaluationOutcome
from s3bootscript_analyzer.analysis.contracts import ReportRenderer

RENDERED_REPORT = "Rendered analysis report\n"
pytestmark = pytest.mark.usefixtures("renderer")


@dataclass
class RecordingRenderer(ReportRenderer):
    reports: list[AnalysisReport] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)

    def select(self, output_format: str) -> ReportRenderer:
        self.formats.append(output_format)
        return self

    def render(self, report: AnalysisReport) -> str:
        self.reports.append(report)
        return RENDERED_REPORT


@pytest.fixture(name="renderer")
def _renderer(monkeypatch: MonkeyPatch) -> RecordingRenderer:
    result = RecordingRenderer()
    monkeypatch.setattr(cli, "build_report_renderer", result.select)
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")
    return result


@pytest.fixture(name="binary_path")
def _binary_path(tmp_path: Path) -> Path:
    # UInt8 MEM_WRITE records followed by TERMINATE, with a valid table header.
    records = (
        struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x1800, 1)
        + struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x3000, 2)
        + struct.pack("<HB", 0xFF, 3)
    )
    path = tmp_path / "two-writes.bin"
    path.write_bytes(struct.pack("<HBHIHH", 0xAA, 13, 1, 13 + len(records), 0, 0) + records)
    return path


@pytest.fixture(name="rule_path")
def _rule_path(tmp_path: Path) -> Path:
    return _write_rule(tmp_path, "S3-WRITE", "ADDR == 0x1800")


@pytest.fixture(name="analysis_arguments")
def _analysis_arguments(binary_path: Path, rule_path: Path) -> list[str]:
    return _arguments(binary_path, rule_path)


def _write_rule(
    directory: Path, rule_id: str, expression: str, required_fields: tuple[str, ...] = ()
) -> Path:
    path = directory / f"{rule_id}.yaml"
    path.write_text(
        f"""\
schema_version: 1
plugin: s3bootscript
metadata:
  id: {rule_id}
  title: Selected memory write
  severity: warning
profile:
  required_fields: {list(required_fields)}
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: mem[$ADDR] <- $VALUE
condition:
  language: simpleeval
  expression: >-
    {expression}
""",
        encoding="utf-8",
    )
    return path


def _arguments(binary_path: Path, rule_path: Path) -> list[str]:
    return ["analyze", "--input-binary", str(binary_path), "--rule", str(rule_path)]


def test_selected_profile_filters_binary_writes_and_preserves_evidence(
    binary_path: Path, tmp_path: Path, renderer: RecordingRenderer
) -> None:
    # Arrange
    rule = _write_rule(tmp_path, "S3-PROFILE-WRITE", 'ADDR == profile["address"]')
    profile = tmp_path / "producer.json"
    profile.write_text('{"address": 6144}', encoding="utf-8")

    # Act / Assert
    assert cli.main(_arguments(binary_path, rule) + ["--profile", str(profile)]) == 3
    assert renderer.reports[0].artifact_name == "two-writes.bin"
    assert renderer.reports[0].profile_name == "producer.json"
    assert renderer.reports[0].evaluations[0].outcome is EvaluationOutcome.MATCHED
    evidence = renderer.reports[0].evaluations[0].evidence
    assert len(evidence) == 1
    assert evidence[0].bindings == {"ADDR": 0x1800, "VALUE": 1}
    assert evidence[0].semantic_text == "mem[0x1800] <- 0x01"
    assert evidence[0].record_index == 0
    assert evidence[0].opcode_offset == 0x0D
    assert evidence[0].record["fields"] == {
        "width": 0,
        "count": 1,
        "address": 0x1800,
        "buffer": (1,),
    }


def test_no_matching_writes_returns_success(
    binary_path: Path, tmp_path: Path, renderer: RecordingRenderer
) -> None:
    rule = _write_rule(tmp_path, "S3-NO-WRITE", "ADDR == 0x4000")

    exit_code = cli.main(_arguments(binary_path, rule))

    assert exit_code == 0
    assert renderer.reports[0].evaluations[0].outcome is EvaluationOutcome.NOT_MATCHED


def test_repeated_rule_paths_preserve_the_selected_order(
    binary_path: Path, rule_path: Path, tmp_path: Path, renderer: RecordingRenderer
) -> None:
    later_rule = _write_rule(tmp_path, "S3-LATER", "ADDR == 0x3000")

    exit_code = cli.main(_arguments(binary_path, later_rule) + ["--rule", str(rule_path)])

    assert exit_code == 3
    assert tuple(item.rule.rule_id for item in renderer.reports[0].evaluations) == (
        "S3-LATER",
        "S3-WRITE",
    )


def test_omitted_profile_is_empty_and_missing_declared_facts_remain_unknown(
    binary_path: Path, tmp_path: Path, renderer: RecordingRenderer
) -> None:
    rule = _write_rule(tmp_path, "S3-REQUIRES-FACTS", 'ADDR == profile["address"]', ("address",))

    exit_code = cli.main(_arguments(binary_path, rule))

    assert exit_code == 0
    assert renderer.reports[0].profile_name == "default"
    assert renderer.reports[0].evaluations[0].outcome is EvaluationOutcome.UNKNOWN
    assert renderer.reports[0].evaluations[0].evidence == ()


@pytest.mark.parametrize("output_format", ["markdown", "html"])
def test_requested_format_is_rendered_to_stdout(
    analysis_arguments: list[str],
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
    output_format: str,
) -> None:
    arguments = analysis_arguments + ["--output-format", output_format]

    exit_code = cli.main(arguments)

    assert exit_code == 3
    assert renderer.formats == [output_format]
    assert capsys.readouterr().out == RENDERED_REPORT


def test_default_markdown_report_is_written_to_selected_file(
    analysis_arguments: list[str],
    tmp_path: Path,
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
) -> None:
    output = tmp_path / "report.md"

    exit_code = cli.main(analysis_arguments + ["--output-report", str(output)])

    assert exit_code == 3
    assert renderer.formats == ["markdown"]
    assert output.read_text(encoding="utf-8") == RENDERED_REPORT
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("arguments", "reason", "option"),
    [
        (["--rule", "rule.yaml"], "required", "--input-binary"),
        (["--input-binary", "input.bin"], "required", "--rule"),
        (
            ["--input-binary", "input.bin", "--rule", "rule.yaml", "--output-format", "xml"],
            "invalid",
            "--output-format",
        ),
        (
            ["--input-binary", "input.bin", "--rule", "rule.yaml", "--debug", "--quiet"],
            "not allowed with argument",
            "--quiet",
        ),
    ],
    ids=["missing-binary", "missing-rule", "unsupported-format", "conflicting-verbosity"],
)
def test_invalid_invocation_reports_the_specific_usage_error(
    arguments: list[str], reason: str, option: str, capsys: CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["analyze", *arguments])

    diagnostic = capsys.readouterr().err
    assert error.value.code == 2
    assert "usage: s3bootscript-analyzer analyze" in diagnostic
    assert reason in diagnostic
    assert option in diagnostic


@pytest.mark.parametrize(
    "missing_option", ["--input-binary", "--rule"], ids=["unreadable-binary", "unreadable-rule"]
)
def test_unreadable_input_reports_the_path_on_stderr(
    analysis_arguments: list[str],
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
    missing_option: str,
) -> None:
    missing = Path(analysis_arguments[2]).with_name("missing-input")
    analysis_arguments[analysis_arguments.index(missing_option) + 1] = str(missing)

    exit_code = cli.main(analysis_arguments)

    assert exit_code == 1
    assert str(missing) in capsys.readouterr().err
    assert renderer.reports == []


@pytest.mark.parametrize("contents", ["{invalid", "[]"], ids=["malformed-json", "non-object-json"])
def test_invalid_selected_profile_is_an_error_without_default_fallback(
    analysis_arguments: list[str],
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
    contents: str,
) -> None:
    profile = Path(analysis_arguments[2]).with_name("invalid-profile.json")
    profile.write_text(contents, encoding="utf-8")

    exit_code = cli.main(analysis_arguments + ["--profile", str(profile)])

    assert exit_code == 1
    assert str(profile) in capsys.readouterr().err
    assert renderer.reports == []


def test_undecodable_binary_reports_an_error(
    binary_path: Path, rule_path: Path, renderer: RecordingRenderer, capsys: CaptureFixture[str]
) -> None:
    binary_path.write_bytes(b"\xaa")

    exit_code = cli.main(_arguments(binary_path, rule_path))

    assert exit_code == 1
    assert "parse" in capsys.readouterr().err.lower()
    assert renderer.reports == []


def test_no_usable_rules_reports_a_setup_error(
    binary_path: Path, rule_path: Path, renderer: RecordingRenderer, capsys: CaptureFixture[str]
) -> None:
    rule_path.write_text("{}", encoding="utf-8")

    exit_code = cli.main(_arguments(binary_path, rule_path))

    assert exit_code == 1
    assert "at least one valid compatible rule" in capsys.readouterr().err
    assert renderer.reports == []


def test_output_failure_takes_precedence_over_a_match(
    binary_path: Path,
    rule_path: Path,
    tmp_path: Path,
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
) -> None:
    exit_code = cli.main(_arguments(binary_path, rule_path) + ["--output-report", str(tmp_path)])

    assert exit_code == 1
    assert str(tmp_path) in capsys.readouterr().err
    assert renderer.reports[0].evaluations[0].outcome is EvaluationOutcome.MATCHED


def test_condition_error_preserves_later_finding_and_returns_failure(
    binary_path: Path,
    rule_path: Path,
    renderer: RecordingRenderer,
    capsys: CaptureFixture[str],
) -> None:
    broken = _write_rule(rule_path.parent, "S3-BROKEN", 'ADDR >= profile["missing"]')

    exit_code = cli.main(_arguments(binary_path, broken) + ["--rule", str(rule_path)])

    assert exit_code == 1
    assert tuple(item.outcome for item in renderer.reports[0].evaluations) == (
        EvaluationOutcome.ERROR,
        EvaluationOutcome.MATCHED,
    )
    assert renderer.reports[0].evaluations[0].diagnostics[0].code == "rule_execution_error"
    assert capsys.readouterr().out == RENDERED_REPORT


def test_debug_keeps_diagnostics_on_stderr_and_report_on_stdout(
    analysis_arguments: list[str], capsys: CaptureFixture[str]
) -> None:
    exit_code = cli.main(analysis_arguments + ["--debug"])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert captured.out == RENDERED_REPORT
    assert "Debug:" in captured.err


def test_quiet_retains_requested_report_without_informational_output(
    analysis_arguments: list[str], capsys: CaptureFixture[str]
) -> None:
    exit_code = cli.main(analysis_arguments + ["--quiet"])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert captured.out == RENDERED_REPORT
    assert captured.err == ""


def test_quiet_retains_operational_errors(
    binary_path: Path, rule_path: Path, capsys: CaptureFixture[str]
) -> None:
    missing = binary_path.with_name("missing.bin")

    exit_code = cli.main(_arguments(missing, rule_path) + ["--quiet"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert str(missing) in captured.err
    assert captured.out == ""
