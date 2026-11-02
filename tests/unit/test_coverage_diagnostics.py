"""Public command-line checks for coverage diagnostics."""

import subprocess
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
RUNNER = REPOSITORY / "scripts" / "coverage-diagnostics"
RUNNER_SPEC = spec_from_file_location(
    "coverage_diagnostics_runner", REPOSITORY / "tools/coverage_diagnostics/runner.py"
)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
RUNNER_MODULE = module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER_MODULE)
_summary = RUNNER_MODULE.__dict__["_summary"]


def test_help_describes_required_output_directory() -> None:
    result = subprocess.run([str(RUNNER), "--help"], capture_output=True, text=True, check=False)

    assert result.returncode == 0
    assert "--output-dir" in result.stdout


def test_existing_output_directory_is_rejected_without_changing_it(tmp_path: Path) -> None:
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    marker = output_dir / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")

    result = subprocess.run(
        [str(RUNNER), "--output-dir", str(output_dir)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert marker.read_text(encoding="utf-8") == "preserve"


def test_output_directory_must_be_outside_repository() -> None:
    output_dir = REPOSITORY / "coverage-output-test"

    result = subprocess.run(
        [str(RUNNER), "--output-dir", str(output_dir)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert not output_dir.exists()


def test_summary_groups_sources_into_named_subsystems() -> None:
    report = _summary(
        {
            "files": {
                "s3bootscript_analyzer/analysis/engine.py": {
                    "summary": {"num_statements": 2, "covered_lines": 1}
                },
                "s3bootscript_analyzer/reporting/report.py": {
                    "summary": {"num_statements": 3, "covered_lines": 3}
                },
            },
            "totals": {"num_statements": 5, "covered_lines": 4},
        }
    )

    assert report["subsystems"]["analysis"]["statements"] == 2
    assert report["subsystems"]["reporting"]["covered_statements"] == 3
    assert report["aggregate"]["num_statements"] == 5


def test_summary_rejects_unmapped_source_paths() -> None:
    with pytest.raises(ValueError, match="unmapped coverage source"):
        _summary({"files": {"s3bootscript_analyzer/unclassified.py": {"summary": {}}}})
