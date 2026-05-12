from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from s3bootscript_analyzer import cli
from s3bootscript_analyzer.cli import EXIT_FAILURE, EXIT_SUCCESS, main
from s3bootscript_analyzer.errors import BinaryLoadError
from s3bootscript_analyzer.reporting import (
    BootScriptRenderer,
    JsonIrRenderer,
    SemanticIrRenderer,
    TextIrRenderer,
)


class FakeDisassembler:
    def __init__(self, output: str) -> None:
        self._output = output

    def execute(self, _path: Path) -> str:
        return self._output


class FailingDisassembler:
    def execute(self, _path: Path) -> str:
        raise BinaryLoadError("wrapped load failure")


class CausedFailingDisassembler:
    def execute(self, _path: Path) -> str:
        try:
            raise ValueError("root cause")
        except ValueError as ex:
            raise BinaryLoadError("wrapped load failure") from ex


def test_main_returns_success(capsys: CaptureFixture[str]) -> None:
    exit_code = main([])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert "scaffold ready" in captured.out


def test_main_reports_missing_input(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    exit_code = main(["--input-binary", str(tmp_path / "missing.bin")])
    captured = capsys.readouterr()

    assert exit_code == EXIT_FAILURE
    assert "Unable to load input binary" in captured.out


@pytest.mark.parametrize(
    ("output_format", "renderer_type"),
    [
        ("text", TextIrRenderer),
        ("json", JsonIrRenderer),
        ("semantic", SemanticIrRenderer),
    ],
)
def test_main_accepts_valid_output_formats(
    output_format: str,
    renderer_type: type[BootScriptRenderer],
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:
    captured_renderer = _patch_successful_disassembler(monkeypatch)

    assert (
        main(["--input-binary", str(tmp_path / "input.bin"), "--output-format", output_format])
        == EXIT_SUCCESS
    )

    assert capsys.readouterr().out == "rendered\n"
    assert isinstance(captured_renderer[0], renderer_type)


def test_main_rejects_invalid_output_format() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--input-binary", "input.bin", "--output-format", "xml"])

    assert exc_info.value.code == 2


def test_main_writes_output_to_stdout(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:
    _patch_successful_disassembler(monkeypatch, "stdout output\n")

    exit_code = main(["--input-binary", str(tmp_path / "input.bin")])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert captured.out == "stdout output\n"


def test_main_writes_output_to_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    output_path = tmp_path / "report.txt"
    _patch_successful_disassembler(monkeypatch, "file output\n")

    exit_code = main(
        [
            "--input-binary",
            str(tmp_path / "input.bin"),
            "--output-report",
            str(output_path),
        ]
    )

    assert exit_code == EXIT_SUCCESS
    assert output_path.read_text(encoding="utf-8") == "file output\n"


def test_main_accepts_debug_and_writes_diagnostics_to_stderr(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:
    _patch_successful_disassembler(monkeypatch)

    exit_code = main(["--input-binary", str(tmp_path / "input.bin"), "--debug"])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert captured.out == "rendered\n"
    assert "Debug: debug logging enabled" in captured.err
    assert "Debug:" not in captured.out


def test_main_wraps_expected_analyzer_errors(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:

    def fake_build_default_disassembler(
        renderer: BootScriptRenderer | None = None, verbose: bool = False
    ) -> FailingDisassembler:
        assert renderer is not None
        assert verbose is False
        return FailingDisassembler()

    monkeypatch.setattr(cli, "build_default_disassembler", fake_build_default_disassembler)

    exit_code = main(["--input-binary", str(tmp_path / "input.bin")])
    captured = capsys.readouterr()

    assert exit_code == EXIT_FAILURE
    assert captured.out == "Error: wrapped load failure\n"
    assert captured.err == ""


def test_main_debug_logs_expected_analyzer_error_cause(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:

    def fake_build_default_disassembler(
        renderer: BootScriptRenderer | None = None, verbose: bool = False
    ) -> CausedFailingDisassembler:
        assert renderer is not None
        assert verbose is False
        return CausedFailingDisassembler()

    monkeypatch.setattr(cli, "build_default_disassembler", fake_build_default_disassembler)

    exit_code = main(["--input-binary", str(tmp_path / "input.bin"), "--debug"])
    captured = capsys.readouterr()

    assert exit_code == EXIT_FAILURE
    assert captured.out == "Error: wrapped load failure\n"
    assert "Debug: analyzer error type=BinaryLoadError message=wrapped load failure" in captured.err
    assert "Debug: analyzer error cause type=ValueError message=root cause" in captured.err


def _patch_successful_disassembler(
    monkeypatch: MonkeyPatch,
    output: str = "rendered\n",
) -> list[BootScriptRenderer]:
    captured_renderer: list[BootScriptRenderer] = []

    def fake_build_default_disassembler(
        renderer: BootScriptRenderer | None = None, verbose: bool = False
    ) -> FakeDisassembler:
        assert renderer is not None
        assert verbose is False
        captured_renderer.append(renderer)
        return FakeDisassembler(output)

    monkeypatch.setattr(cli, "build_default_disassembler", fake_build_default_disassembler)
    return captured_renderer
