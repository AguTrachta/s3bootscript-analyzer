"""Installed CLI acceptance stories with real parsing, matching, and rendering."""

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from pytest import MonkeyPatch

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


def _run_analysis(
    binary: Path, profile: Path, *output_options: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "s3bootscript-analyzer",
            "analyze",
            "--input-binary",
            str(binary),
            "--rule",
            str(BASE_RULE),
            "--profile",
            str(profile),
            *output_options,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_installed_command_prints_profile_filtered_report(
    binary_path: Path, profile_path: Path
) -> None:
    # Act
    completed = _run_analysis(binary_path, profile_path)

    # Assert
    assert completed.returncode == 3, completed.stderr
    assert "two-writes.bin" in completed.stdout
    assert "kernel.json" in completed.stdout
    assert RULE_ID in completed.stdout
    assert "mem[0x1800] <- 0x01" in completed.stdout
    assert "mem[0x3000]" not in completed.stdout


def test_installed_command_writes_profile_filtered_report_to_file(
    binary_path: Path, profile_path: Path, tmp_path: Path
) -> None:
    # Arrange
    report_path = tmp_path / "analysis.md"

    # Act
    completed = _run_analysis(binary_path, profile_path, "--output-report", str(report_path))

    # Assert
    assert completed.returncode == 3, completed.stderr
    assert completed.stdout == ""
    report = report_path.read_text(encoding="utf-8")
    assert RULE_ID in report
    assert "mem[0x1800] <- 0x01" in report
    assert "mem[0x3000]" not in report
