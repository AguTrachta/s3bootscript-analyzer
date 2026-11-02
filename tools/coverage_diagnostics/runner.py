"""Collect independent line and branch coverage evidence for the project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
GENERATED = "*/parsers/generated/*"
SUBSYSTEM_BY_AREA = {
    "analysis": "analysis",
    "ingest": "ingestion_parsing",
    "parsers": "ingestion_parsing",
    "engine": "engine_ir",
    "ir": "engine_ir",
    "matchers": "rules_plugins_profiles",
    "plugins": "rules_plugins_profiles",
    "profile_data": "rules_plugins_profiles",
    "rules": "rules_plugins_profiles",
    "reporting": "reporting",
}
ROOT_MODULES = {
    "__init__.py",
    "application.py",
    "cli.py",
    "cli_analysis.py",
    "errors.py",
    "extensions.py",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="Fresh directory outside the repository"
    )
    return parser


def _validate_output(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.exists():
        raise ValueError(f"Output directory already exists: {resolved}")
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError("Output directory must be outside the repository")
    resolved.mkdir(parents=True)
    return resolved


def _phase(output: Path, name: str, branch: bool, args: list[str]) -> dict[str, Any]:
    phase_dir = output / "raw" / name
    phase_dir.mkdir(parents=True)
    config = output / f"{name}.ini"
    _write_coverage_config(config, branch)
    child_dir = _child_directory(phase_dir, name)
    if name == "acceptance-child-proof":
        _write_child_config(child_dir, branch)
    command = _phase_command(output, name, args)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=_phase_environment(config, phase_dir, name, child_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    log = output / f"{name}.log"
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    record = _phase_record(command, result.returncode, log, output / f"{name}.xml", branch)
    return _add_child_proof(record, child_dir, name)


def _write_coverage_config(config: Path, branch: bool) -> None:
    config.write_text(
        f"[run]\nsource = s3bootscript_analyzer\nomit = {GENERATED}\n"
        f"branch = {str(branch)}\nparallel = True\nrelative_files = True\n"
        "patch = subprocess\ncore = ctrace\n",
        encoding="utf-8",
    )


def _write_child_config(child_dir: Path, branch: bool) -> None:
    config = child_dir / "coverage.ini"
    _write_coverage_config(config, branch)
    with config.open("a", encoding="utf-8") as file:
        file.write(f"data_file = {child_dir / '.coverage'}\n")


def _child_directory(phase_dir: Path, name: str) -> Path:
    child_dir = phase_dir / "children"
    if name == "acceptance-child-proof":
        child_dir.mkdir()
    return child_dir


def _phase_environment(config: Path, phase_dir: Path, name: str, child_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({"COVERAGE_RCFILE": str(config), "COVERAGE_FILE": str(phase_dir / ".coverage")})
    if name == "acceptance-child-proof":
        env["S3_ACCEPTANCE_CHILD_COVERAGE_START"] = str(child_dir / "coverage.ini")
    return env


def _phase_command(output: Path, name: str, args: list[str]) -> list[str]:
    return [
        "uv",
        "run",
        "--locked",
        "python",
        "-m",
        "coverage",
        "run",
        "-m",
        "pytest",
        *args,
        f"--junitxml={output / f'{name}.xml'}",
    ]


def _phase_record(
    command: list[str], exit_code: int, log: Path, junit: Path, branch: bool
) -> dict[str, Any]:
    return {
        "command": command,
        "exit_code": exit_code,
        "log": log.name,
        "branch": branch,
        "junit": _junit_summary(junit),
    }


def _add_child_proof(record: dict[str, Any], child_dir: Path, name: str) -> dict[str, Any]:
    if name == "acceptance-child-proof":
        child_files = list(child_dir.glob(".coverage*"))
        record["child_coverage_files"] = len(child_files)
        record["child_proof"] = bool(child_files)
    return record


def _junit_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"available": False, "tests": 0, "failures": 0, "errors": 0, "skips": []}
    cases = list(ElementTree.parse(path).getroot().iter("testcase"))
    return {
        "available": True,
        "tests": len(cases),
        "failures": sum(len(case.findall("failure")) for case in cases),
        "errors": sum(len(case.findall("error")) for case in cases),
        "skips": _skip_reasons(cases),
    }


def _skip_reasons(cases: list[ElementTree.Element]) -> list[dict[str, str]]:
    skips = []
    for case in cases:
        skips.extend(_case_skips(case))
    return skips


def _case_skips(case: ElementTree.Element) -> list[dict[str, str]]:
    return [
        {
            "test": case.get("name", "unknown"),
            "reason": item.get("message", "") or item.text or "unspecified",
        }
        for item in case.findall("skipped")
    ]


def _tool_version(executable: str, arguments: list[str]) -> dict[str, str | bool]:
    if shutil.which(executable) is None:
        return {"available": False, "version": "unavailable"}
    result = subprocess.run([executable, *arguments], capture_output=True, text=True, check=False)
    output = (result.stdout or result.stderr).splitlines()
    return {"available": result.returncode == 0, "version": output[0] if output else "unknown"}


def _native_versions() -> dict[str, dict[str, str | bool]]:
    return {
        "nix": _tool_version("nix", ["--version"]),
        "c_compiler": _tool_version("cc", ["--version"]),
        "kaitai_compiler": _tool_version("kaitai-struct-compiler", ["--version"]),
        "ast_grep": _tool_version("ast-grep", ["--version"]),
    }


def _repo_identity() -> dict[str, str | bool]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    changes = subprocess.run(
        ["git", "diff", "--binary", "HEAD"], cwd=ROOT, capture_output=True, check=False
    )
    return {
        "revision": revision.stdout.strip(),
        "dirty": bool(dirty.stdout.strip()),
        "dirty_hash": hashlib.sha256(changes.stdout + dirty.stdout.encode()).hexdigest(),
        "status_hash": hashlib.sha256(dirty.stdout.encode()).hexdigest(),
    }


def _source_hash() -> str:
    source_hash = hashlib.sha256()
    source_paths = sorted((ROOT / "src").rglob("*.py"))
    for source_path in source_paths:
        if "generated" in source_path.parts:
            continue
        source_hash.update(source_path.relative_to(ROOT).as_posix().encode())
        source_hash.update(source_path.read_bytes())
    return source_hash.hexdigest()


def _input_hashes() -> dict[str, str]:
    hashes = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ("pyproject.toml", "uv.lock")
    }
    hashes["source"] = _source_hash()
    return hashes


def _skips(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"phase": record["log"], **skip}
        for record in records
        for skip in record.get("junit", {}).get("skips", [])
    ]


def _failures(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if _has_failure(record)]


def _has_failure(record: dict[str, Any]) -> bool:
    if record["exit_code"] != 0:
        return True
    if not record.get("junit", {}).get("available", True):
        return True
    return "child_proof" in record and not record["child_proof"]


def _metadata(records: list[dict[str, Any]], prerequisites: dict[str, Any]) -> dict[str, Any]:
    identity = _repo_identity()
    return {
        "created_at": datetime.now(UTC).isoformat(),
        **identity,
        "python": sys.version,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
        },
        "tool_versions": prerequisites,
        "hashes": _input_hashes(),
        "installation_mode": {
            "acceptance_mode": os.environ.get("S3_ACCEPTANCE_MODE", "development"),
            "executable": os.environ.get(
                "S3_ANALYZER_EXECUTABLE", "installed console script from uv environment"
            ),
        },
        "commands": records,
        "skips": _skips(records),
        "failures": _failures(records),
    }


def _package_area(filename: str) -> str:
    parts = Path(filename).parts
    if "s3bootscript_analyzer" not in parts:
        raise ValueError(f"unmapped coverage source: {filename}")
    package_index = parts.index("s3bootscript_analyzer")
    if package_index + 1 == len(parts):
        raise ValueError(f"unmapped coverage source: {filename}")
    return parts[package_index + 1]


def _subsystem(filename: str) -> str:
    area = _package_area(filename)
    if area in ROOT_MODULES:
        return "cli_application"
    if area in SUBSYSTEM_BY_AREA:
        return SUBSYSTEM_BY_AREA[area]
    raise ValueError(f"unmapped coverage source: {filename}")


def _summary(data: dict[str, Any]) -> dict[str, Any]:
    files = data.get("files", {})
    subsystems: dict[str, dict[str, int]] = {}
    for filename, details in files.items():
        key = _subsystem(filename)
        summary = details["summary"]
        target = subsystems.setdefault(
            key, {"statements": 0, "covered_statements": 0, "branches": 0, "covered_branches": 0}
        )
        for metric, source in (
            ("statements", "num_statements"),
            ("covered_statements", "covered_lines"),
            ("branches", "num_branches"),
            ("covered_branches", "covered_branches"),
        ):
            target[metric] += int(summary.get(source, 0))
    return {"aggregate": data.get("totals", {}), "subsystems": subsystems}


def _run_tests(output: Path) -> list[dict[str, Any]]:
    return [
        _phase(output, "line-suite", False, []),
        _phase(output, "branch-suite", True, []),
        _phase(output, "acceptance-child-proof", True, ["tests/acceptance"]),
    ]


def _combine(output: Path, config: Path, phases: list[Path], data_name: str) -> dict[str, Any]:
    data_paths = sorted(path for phase in phases for path in phase.glob(".coverage*"))
    command = [
        "uv",
        "run",
        "--locked",
        "python",
        "-m",
        "coverage",
        "combine",
        "--keep",
        "--rcfile",
        str(config),
        *(str(path) for path in data_paths),
    ]
    data_file = output / data_name
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=os.environ | {"COVERAGE_FILE": str(data_file)},
        capture_output=True,
        text=True,
        check=False,
    )
    log_name = f"combine-{data_name}.log"
    (output / log_name).write_text(result.stdout + result.stderr, encoding="utf-8")
    return {"command": command, "exit_code": result.returncode, "log": log_name}


def _report(
    output: Path, config: Path, data_file: Path, report_format: str, prefix: str
) -> dict[str, Any]:
    name = _report_name(report_format, prefix)
    _prepare_report_target(output, name, report_format)
    command = _report_command(config, output, report_format, name)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=os.environ | {"COVERAGE_FILE": str(data_file)},
        capture_output=True,
        text=True,
        check=False,
    )
    log = f"{name}.log"
    (output / log).write_text(result.stdout + result.stderr, encoding="utf-8")
    _write_text_report(output, name, report_format, result.returncode, result.stdout)
    return {"command": command, "exit_code": result.returncode, "log": log}


def _report_name(report_format: str, prefix: str) -> str:
    if report_format == "json":
        return f"{prefix + '-' if prefix else ''}coverage.json"
    stem = {"report": "text"}.get(report_format, report_format)
    return f"{prefix}-{stem}" if prefix else stem


def _prepare_report_target(output: Path, name: str, report_format: str) -> None:
    if report_format == "html":
        (output / name).mkdir(exist_ok=True)


def _report_command(config: Path, output: Path, report_format: str, name: str) -> list[str]:
    command = [
        "uv",
        "run",
        "--locked",
        "python",
        "-m",
        "coverage",
        report_format,
        "--rcfile",
        str(config),
    ]
    if report_format == "json":
        command.extend(["-o", str(output / name)])
    if report_format == "html":
        command.extend(["-d", str(output / name)])
    return command


def _write_text_report(
    output: Path, name: str, report_format: str, exit_code: int, text: str
) -> None:
    if report_format == "report" and exit_code == 0:
        (output / f"{name}.txt").write_text(text, encoding="utf-8")


def _reports(output: Path, config: Path, data_file: Path, prefix: str) -> list[dict[str, Any]]:
    return [
        _report(output, config, data_file, report_format, prefix)
        for report_format in ("json", "html", "report")
    ]


def _combine_all(output: Path) -> list[dict[str, Any]]:
    line_phase = output / "raw" / "line-suite"
    branch_phases = [
        output / "raw" / "branch-suite",
        output / "raw" / "acceptance-child-proof",
        output / "raw" / "acceptance-child-proof" / "children",
    ]
    return [
        _combine(output, output / "line-suite.ini", [line_phase], "line-combined"),
        _combine(output, output / "branch-suite.ini", branch_phases, "combined"),
    ]


def _all_reports(output: Path) -> list[dict[str, Any]]:
    return [
        *_reports(output, output / "line-suite.ini", output / "line-combined", "line"),
        *_reports(output, output / "branch-suite.ini", output / "combined", ""),
    ]


def _write_summary(output: Path, prefix: str) -> None:
    json_name = f"{prefix + '-' if prefix else ''}coverage.json"
    json_path = output / json_name
    if json_path.exists():
        summary = _summary(json.loads(json_path.read_text(encoding="utf-8")))
        summary_name = f"{prefix}-subsystems.json" if prefix else "subsystems.json"
        (output / summary_name).write_text(json.dumps(summary, indent=2), encoding="utf-8")


def run(output_dir: Path) -> int:
    output = _validate_output(output_dir)
    (output / "raw").mkdir()
    records: list[dict[str, Any]] = []
    prerequisites = subprocess.run(
        ["uv", "run", "--locked", "python", "-m", "coverage", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    prerequisites_info = {
        "exit_code": prerequisites.returncode,
        "version": prerequisites.stdout.strip(),
        "uv": subprocess.run(
            ["uv", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip(),
        "pytest": subprocess.run(
            ["uv", "run", "--locked", "pytest", "--version"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip(),
        "native": _native_versions(),
    }
    if prerequisites.returncode:
        (output / "metadata.json").write_text(
            json.dumps(_metadata(records, prerequisites_info), indent=2), encoding="utf-8"
        )
        return 1
    records.extend(_run_tests(output))
    metadata = _metadata(records, prerequisites_info)
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    if metadata["failures"]:
        return 1
    records.extend(_combine_all(output))
    metadata = _metadata(records, prerequisites_info)
    if metadata["failures"]:
        metadata = _metadata(records, prerequisites_info)
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return 1
    records.extend(_all_reports(output))
    _write_summary(output, "line")
    _write_summary(output, "")
    metadata = _metadata(records, prerequisites_info)
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return int(bool(metadata["failures"]))


def main() -> int:
    args = _parser().parse_args()
    try:
        return run(args.output_dir)
    except (OSError, ValueError) as error:
        print(f"coverage-diagnostics: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
