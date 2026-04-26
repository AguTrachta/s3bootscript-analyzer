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


class FakeUseCase:

    def __init__(self, output: str) -> None:
        self._output = output

    def execute(self, _path: Path) -> str:
        return self._output


class FailingUseCase:

    def execute(self, _path: Path) -> str:
        raise BinaryLoadError("wrapped load failure")


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
    captured_renderer = _patch_successful_use_case(monkeypatch)

    assert main(
        ["--input-binary",
         str(tmp_path / "input.bin"), "--output-format", output_format]
    ) == EXIT_SUCCESS

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
    _patch_successful_use_case(monkeypatch, "stdout output\n")

    exit_code = main(["--input-binary", str(tmp_path / "input.bin")])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert captured.out == "stdout output\n"


def test_main_writes_output_to_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    output_path = tmp_path / "report.txt"
    _patch_successful_use_case(monkeypatch, "file output\n")

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


def test_main_wraps_expected_analyzer_errors(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:

    def fake_build_default_use_case(
        renderer: BootScriptRenderer | None = None, verbose: bool = False
    ) -> FailingUseCase:
        assert renderer is not None
        assert verbose is False
        return FailingUseCase()

    monkeypatch.setattr(cli, "build_default_use_case", fake_build_default_use_case)

    exit_code = main(["--input-binary", str(tmp_path / "input.bin")])
    captured = capsys.readouterr()

    assert exit_code == EXIT_FAILURE
    assert captured.out == "Error: wrapped load failure\n"


def _patch_successful_use_case(
    monkeypatch: MonkeyPatch,
    output: str = "rendered\n",
) -> list[BootScriptRenderer]:
    captured_renderer: list[BootScriptRenderer] = []

    def fake_build_default_use_case(
        renderer: BootScriptRenderer | None = None, verbose: bool = False
    ) -> FakeUseCase:
        assert renderer is not None
        assert verbose is False
        captured_renderer.append(renderer)
        return FakeUseCase(output)

    monkeypatch.setattr(cli, "build_default_use_case", fake_build_default_use_case)
    return captured_renderer
