"""Real binary-to-report stories, without replacing analysis or reporting adapters."""

import json
import os
import re
import struct
import sys
from html import unescape
from pathlib import Path

import pytest
import yaml
from pytest import CaptureFixture, MonkeyPatch

from s3bootscript_analyzer import cli

BASE_RULE = Path(__file__).resolve().parents[2] / "rules/base/kernel-write.rule.yaml"
RULE_ID = "S3-KERNEL-WRITE-001"
pytestmark = pytest.mark.usefixtures("matcher_path")


@pytest.fixture(name="matcher_path")
def _matcher_path(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")


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
    return _write_rule(tmp_path, "SELECTED-WRITE", "ADDR == 0x1800")


def _arguments(binary: Path, rule: Path) -> list[str]:
    return [
        "analyze",
        "--input-binary",
        str(binary),
        "--rule",
        str(rule),
    ]


def _write_rule(
    directory: Path,
    rule_id: str,
    expression: str,
    *,
    enabled: bool = True,
    required_fields: tuple[str, ...] = (),
) -> Path:
    path = directory / f"{rule_id}.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "plugin": "s3bootscript",
                "metadata": {
                    "id": rule_id,
                    "title": "Selected memory write",
                    "severity": "warning",
                    "enabled": enabled,
                },
                "profile": {"required_fields": list(required_fields)},
                "matcher": {
                    "type": "ast_grep",
                    "config": {"language": "s3boot", "rule": {"pattern": "mem[$ADDR] <- $VALUE"}},
                },
                "condition": {"language": "simpleeval", "expression": expression},
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("output_format", ["markdown", "html"])
def test_real_binary_report_contains_only_profile_accepted_evidence(
    binary_path: Path,
    profile_path: Path,
    output_format: str,
    capsys: CaptureFixture[str],
) -> None:
    exit_code = cli.main(
        _arguments(binary_path, BASE_RULE)
        + ["--profile", str(profile_path), "--output-format", output_format]
    )

    output = unescape(capsys.readouterr().out)
    assert exit_code == 3
    assert "two-writes.bin" in output
    assert "kernel.json" in output
    assert RULE_ID in output
    assert re.search(r"\bmatched\b", output, re.IGNORECASE)
    assert "mem[0x1800] <- 0x01" in output
    assert "mem[0x3000]" not in output
    assert re.search(r"\boffset\b", output, re.IGNORECASE)
    assert re.search(r"\b(?:0x0*d|13)\b", output, re.IGNORECASE)


def test_default_markdown_report_is_written_to_the_requested_file(
    binary_path: Path, rule_path: Path, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    output_path = tmp_path / "report.md"

    exit_code = cli.main(_arguments(binary_path, rule_path) + ["--output-report", str(output_path)])

    assert exit_code == 3
    assert "SELECTED-WRITE" in output_path.read_text(encoding="utf-8")
    assert re.search(r"^#{1,6} \S", output_path.read_text(encoding="utf-8"), re.MULTILINE)
    assert capsys.readouterr().out == ""


def test_no_match_is_reported_with_the_rules_declared_warning_severity(
    binary_path: Path, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    rule = _write_rule(tmp_path, "ABSENT-WRITE", "ADDR == 0x4000")

    exit_code = cli.main(_arguments(binary_path, rule))

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "ABSENT-WRITE" in output
    assert re.search(r"\bnot[_ -]matched\b", output, re.IGNORECASE)
    assert re.search(r"\bwarning\b", output, re.IGNORECASE)
    assert "mem[0x1800]" not in output


def test_missing_profile_facts_are_reported_as_unknown_with_a_reason(
    binary_path: Path, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    rule = _write_rule(tmp_path, "REQUIRES-RANGES", "ADDR == 0x1800", required_fields=("ranges",))

    exit_code = cli.main(_arguments(binary_path, rule))

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "REQUIRES-RANGES" in output
    assert "default" in output
    assert re.search(r"\bunknown\b", output, re.IGNORECASE)
    assert "missing_profile_data" in output
    assert "ranges" in output


def test_disabled_rule_remains_visible_as_skipped(
    binary_path: Path, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    disabled = _write_rule(tmp_path, "DISABLED-WRITE", "ADDR == 0x1800", enabled=False)

    exit_code = cli.main(_arguments(binary_path, disabled))

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "DISABLED-WRITE" in output
    assert re.search(r"\bskipped\b", output, re.IGNORECASE)
    assert "mem[0x1800]" not in output


def test_invalid_rule_diagnostic_and_valid_finding_share_the_report(
    binary_path: Path, rule_path: Path, capsys: CaptureFixture[str]
) -> None:
    broken = rule_path.with_name("broken.yaml")
    broken.write_text("metadata: [unterminated", encoding="utf-8")

    exit_code = cli.main(_arguments(binary_path, rule_path) + ["--rule", str(broken)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "invalid_yaml" in captured.out
    assert "broken.yaml" in captured.out
    assert "Invalid YAML" in captured.out
    assert "SELECTED-WRITE" in captured.out
    assert "mem[0x1800] <- 0x01" in unescape(captured.out)
    assert "broken.yaml" in captured.err


def test_condition_failure_does_not_hide_the_later_finding(
    binary_path: Path, rule_path: Path, capsys: CaptureFixture[str]
) -> None:
    broken = _write_rule(rule_path.parent, "BROKEN-CONDITION", 'ADDR == profile["missing"]')

    exit_code = cli.main(_arguments(binary_path, broken) + ["--rule", str(rule_path)])

    output = unescape(capsys.readouterr().out)
    assert exit_code == 1
    assert "BROKEN-CONDITION" in output
    assert "SELECTED-WRITE" in output
    assert "rule_execution_error" in output
    assert "missing" in output
    assert "mem[0x1800] <- 0x01" in output
