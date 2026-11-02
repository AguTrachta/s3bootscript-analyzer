"""Public CLI stories, shared by development and isolated artifact diagnostics."""

import json
import os
import struct
import subprocess
import sys
from collections.abc import Callable
from html import unescape
from pathlib import Path

import pytest

BASE_RULE = Path(__file__).resolve().parents[2] / "rules/base/kernel-write.rule.yaml"
RULE_ID = "S3-KERNEL-WRITE-001"
SEMANTIC_TEXT = "mem[0x1800] <- 0x01\nmem[0x3000] <- 0x02\n"
ERROR_RULE = """schema_version: 1
plugin: s3bootscript
metadata:
  id: BROKEN-CONDITION
  title: Missing fact during evaluation
  severity: warning
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: mem[$ADDR] <- $VALUE
condition:
  language: simpleeval
  expression: 'profile["missing"] == 1'
"""
RunCli = Callable[[list[str]], subprocess.CompletedProcess[str]]


@pytest.fixture(name="executable", scope="session")
def _executable(record_testsuite_property: Callable[[str, object], None]) -> Path:
    mode = os.environ.get("S3_ACCEPTANCE_MODE", "development")
    executable = Path(
        {
            "development": os.environ.get(
                "S3_ANALYZER_EXECUTABLE", str(Path(sys.executable).parent / "s3bootscript-analyzer")
            ),
            "artifact": os.environ.get("S3_ANALYZER_EXECUTABLE", ""),
        }[mode]
    ).resolve(strict=True)
    assert executable.is_file(), "Select a console executable with S3_ANALYZER_EXECUTABLE."
    record_testsuite_property("cli_executable", str(executable))
    record_testsuite_property("installation_mode", mode)
    return executable


def _environment(directory: Path) -> dict[str, str]:
    (directory / "home").mkdir()
    (directory / "empty-bin").mkdir()
    return {
        "HOME": str(directory / "home"),
        "TMPDIR": str(directory),
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    } | {
        "development": {
            "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
            "REPO_ROOT": str(BASE_RULE.parents[2]),
        },
        "artifact": {"PATH": str(directory / "empty-bin")},
    }[os.environ.get("S3_ACCEPTANCE_MODE", "development")]


@pytest.fixture(name="run_cli")
def _run_cli(tmp_path: Path, executable: Path) -> RunCli:
    environment = _environment(tmp_path)

    def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable), *arguments],
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    return run


@pytest.fixture(name="binary_path")
def _binary_path(tmp_path: Path) -> Path:
    records = (
        struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x1800, 1)
        + struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x3000, 2)
        + struct.pack("<HB", 0xFF, 3)
    )
    path = tmp_path / "two-writes.bin"
    path.write_bytes(struct.pack("<HBHIHH", 0xAA, 13, 1, 13 + len(records), 0, 0) + records)
    return path


@pytest.fixture(name="profile_path")
def _profile_path(tmp_path: Path) -> Path:
    path = tmp_path / "kernel.json"
    path.write_text(
        json.dumps({"ranges": [{"name": "KERNEL_CODE_RANGE", "start": 4096, "end": 8191}]}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(name="rule_path")
def _rule_path(tmp_path: Path) -> Path:
    path = tmp_path / "kernel-write.yaml"
    path.write_bytes(BASE_RULE.read_bytes())
    return path


@pytest.fixture(name="error_rule")
def _error_rule(tmp_path: Path) -> Path:
    path = tmp_path / "broken.yaml"
    path.write_text(ERROR_RULE, encoding="utf-8")
    return path


@pytest.fixture(name="analysis_arguments")
def _analysis_arguments(binary_path: Path, rule_path: Path, profile_path: Path) -> list[str]:
    return [*_analyze(binary_path, rule_path), "--profile", str(profile_path)]


def _analyze(binary: Path, rule: Path) -> list[str]:
    return ["analyze", "--input-binary", str(binary), "--rule", str(rule)]


@pytest.mark.parametrize(
    ("output_format", "document_marker"), [("markdown", "# "), ("html", "<html")]
)
def test_installed_command_prints_profile_filtered_report(
    run_cli: RunCli, analysis_arguments: list[str], output_format: str, document_marker: str
) -> None:
    completed = run_cli([*analysis_arguments, "--output-format", output_format])

    assert completed.returncode == 3, completed.stderr
    assert completed.stderr == ""
    assert "two-writes.bin" in completed.stdout
    assert "kernel.json" in completed.stdout
    assert document_marker in completed.stdout.lower()
    assert RULE_ID in completed.stdout
    assert "mem[0x1800] <- 0x01" in unescape(completed.stdout)
    assert "mem[0x3000]" not in completed.stdout


def test_installed_command_writes_profile_filtered_report_to_file(
    run_cli: RunCli, analysis_arguments: list[str], tmp_path: Path
) -> None:
    report_path = tmp_path / "analysis.md"

    completed = run_cli([*analysis_arguments, "--output-report", str(report_path)])

    assert completed.returncode == 3, completed.stderr
    assert completed.stdout == ""
    assert completed.stderr == ""
    report = report_path.read_text(encoding="utf-8")
    assert "# " in report
    assert RULE_ID in report
    assert "mem[0x1800] <- 0x01" in report
    assert "mem[0x3000]" not in report


def test_no_matching_write_returns_zero_with_a_report(
    run_cli: RunCli, analysis_arguments: list[str], profile_path: Path
) -> None:
    profile_path.write_text('{"ranges": []}', encoding="utf-8")

    completed = run_cli(analysis_arguments)

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert RULE_ID in completed.stdout
    assert "not_matched" in completed.stdout


def test_missing_required_profile_facts_remain_unknown(
    run_cli: RunCli, binary_path: Path, rule_path: Path
) -> None:
    completed = run_cli(_analyze(binary_path, rule_path))

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert RULE_ID in completed.stdout
    assert "unknown" in completed.stdout
    assert "missing_profile_data" in completed.stdout


def test_invalid_selected_profile_fails_without_a_report(
    run_cli: RunCli, analysis_arguments: list[str], profile_path: Path, tmp_path: Path
) -> None:
    profile_path.write_text("[]", encoding="utf-8")
    report_path = tmp_path / "analysis.md"

    completed = run_cli([*analysis_arguments, "--output-report", str(report_path)])

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert profile_path.name in completed.stderr
    assert not report_path.exists()


@pytest.mark.parametrize("verbosity", [[], ["--quiet"]], ids=["normal", "quiet"])
def test_unreadable_analysis_input_retains_stderr_errors(
    run_cli: RunCli, rule_path: Path, tmp_path: Path, verbosity: list[str]
) -> None:
    report_path = tmp_path / "analysis.md"

    completed = run_cli(
        [
            *_analyze(tmp_path / "absent.bin", rule_path),
            *verbosity,
            "--output-report",
            str(report_path),
        ]
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "absent.bin" in completed.stderr
    assert not report_path.exists()


def test_output_failure_takes_precedence_over_a_finding(
    run_cli: RunCli, analysis_arguments: list[str], tmp_path: Path
) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("unchanged", encoding="utf-8")

    completed = run_cli([*analysis_arguments, "--output-report", str(parent / "analysis.md")])

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert parent.name in completed.stderr
    assert parent.read_text(encoding="utf-8") == "unchanged"


def test_evaluation_error_preserves_a_later_finding_but_returns_failure(
    run_cli: RunCli, binary_path: Path, rule_path: Path, profile_path: Path, error_rule: Path
) -> None:
    completed = run_cli(
        [
            *_analyze(binary_path, error_rule),
            "--rule",
            str(rule_path),
            "--profile",
            str(profile_path),
        ]
    )

    assert completed.returncode == 1
    assert "BROKEN-CONDITION" in completed.stderr
    assert "BROKEN-CONDITION" in completed.stdout
    assert RULE_ID in completed.stdout
    assert "mem[0x1800] <- 0x01" in completed.stdout


def test_debug_keeps_diagnostics_separate_from_the_report(
    run_cli: RunCli, analysis_arguments: list[str]
) -> None:
    completed = run_cli([*analysis_arguments, "--debug"])

    assert completed.returncode == 3
    assert "Debug:" in completed.stderr
    assert RULE_ID in completed.stdout
    assert "Debug:" not in completed.stdout


def test_quiet_keeps_the_report_without_informational_output(
    run_cli: RunCli, analysis_arguments: list[str]
) -> None:
    completed = run_cli([*analysis_arguments, "--quiet"])

    assert completed.returncode == 3, completed.stderr
    assert completed.stderr == ""
    assert RULE_ID in completed.stdout


def test_debug_and_quiet_conflict_before_creating_a_report(
    run_cli: RunCli, analysis_arguments: list[str], tmp_path: Path
) -> None:
    report_path = tmp_path / "analysis.md"

    completed = run_cli(
        [*analysis_arguments, "--debug", "--quiet", "--output-report", str(report_path)]
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "not allowed" in completed.stderr
    assert not report_path.exists()


def test_disassemble_prints_text_by_default(run_cli: RunCli, binary_path: Path) -> None:
    completed = run_cli(["disassemble", "--input-binary", str(binary_path)])

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert "table_length=56" in completed.stdout
    assert "MEM_WRITE" in completed.stdout
    assert "TERMINATE" in completed.stdout


def test_disassemble_prints_structured_json(run_cli: RunCli, binary_path: Path) -> None:
    completed = run_cli(
        ["disassemble", "--input-binary", str(binary_path), "--output-format", "json"]
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    document = json.loads(completed.stdout)
    assert document["header"]["table_length"] == 56
    assert [(record["mnemonic"], record["offset"]) for record in document["records"]] == [
        ("MEM_WRITE", "0xd"),
        ("MEM_WRITE", "0x21"),
        ("TERMINATE", "0x35"),
    ]


def test_disassemble_prints_semantic_operations(run_cli: RunCli, binary_path: Path) -> None:
    completed = run_cli(
        ["disassemble", "--input-binary", str(binary_path), "--output-format", "semantic"]
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert completed.stdout == SEMANTIC_TEXT


def test_disassemble_writes_the_requested_file(
    run_cli: RunCli, binary_path: Path, tmp_path: Path
) -> None:
    report_path = tmp_path / "disassembly.txt"

    completed = run_cli(
        [
            "disassemble",
            "--input-binary",
            str(binary_path),
            "--output-format",
            "semantic",
            "--output-report",
            str(report_path),
        ]
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert report_path.read_text(encoding="utf-8") == SEMANTIC_TEXT


def test_disassemble_handled_failure_stays_on_stdout(run_cli: RunCli, tmp_path: Path) -> None:
    completed = run_cli(["disassemble", "--input-binary", str(tmp_path / "absent.bin")])

    assert completed.returncode == 1
    assert "absent.bin" in completed.stdout
    assert "Error:" in completed.stdout
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "expected_option"),
    [
        (["--help"], "generate-profile"),
        (["analyze", "--help"], "--rule"),
        (["disassemble", "--help"], "--input-binary"),
    ],
    ids=["root", "analyze", "disassemble"],
)
def test_help_describes_the_public_command(
    run_cli: RunCli, arguments: list[str], expected_option: str
) -> None:
    completed = run_cli(arguments)

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert expected_option in completed.stdout


def test_profile_help_lists_sources_without_collecting(run_cli: RunCli, tmp_path: Path) -> None:
    output = tmp_path / "profile.json"

    completed = run_cli(["generate-profile", "--help", "--profile-output", str(output)])

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "facs" in completed.stdout
    assert "proc-iomem" in completed.stdout
    assert "kernel" in completed.stdout
    assert not output.exists()


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ([], "required"),
        (["analyze"], "required"),
        (["generate-profile"], "--source"),
        (["generate-profile", "--source", "invalid"], "invalid"),
        (["disassemble", "--input-binary", "absent.bin", "--output-format", "invalid"], "invalid"),
    ],
    ids=[
        "missing-command",
        "missing-analysis-input",
        "missing-profile-source",
        "invalid-profile-source",
        "invalid-disassembly-format",
    ],
)
def test_invalid_invocation_fails_without_running_the_command(
    run_cli: RunCli, arguments: list[str], reason: str
) -> None:
    completed = run_cli(arguments)

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert reason in completed.stderr
