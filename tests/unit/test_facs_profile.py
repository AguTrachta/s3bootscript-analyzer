"""Static FACS profile generation from ACPI tables."""

import json
import struct
import subprocess
from pathlib import Path

import pytest
from pytest import CaptureFixture

from s3bootscript_analyzer.cli import build_parser, main
from s3bootscript_analyzer.profile_data import FacsProfileLoader, JsonProfileWriter
from s3bootscript_analyzer.profile_data.commands import CommandSpec, SubprocessRunner
from s3bootscript_analyzer.profile_data.facs import FacsProfileError


class _AcpiTableRunner(SubprocessRunner):
    def __init__(self, table_bytes: dict[str, bytes]) -> None:
        self.table_bytes = table_bytes
        self.specs: list[CommandSpec] = []

    def run(self, spec: CommandSpec) -> subprocess.CompletedProcess[bytes]:
        self.specs.append(spec)
        return subprocess.CompletedProcess(spec.argv, 0, stdout=self.table_bytes[spec.argv[-1]])


class _FailingAcpiTableRunner(SubprocessRunner):
    def run(self, spec: CommandSpec) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.CalledProcessError(1, spec.argv, stderr=b"sudo failed")


def _deny_direct_table_read(_path: Path) -> bytes:
    raise PermissionError("ACPI table requires root")


def _acpi_tables(directory: Path, physical_address: int = 0x3B7CA000) -> tuple[Path, Path]:
    fadt = bytearray(140)
    fadt[:4] = b"FACP"
    struct.pack_into("<I", fadt, 4, len(fadt))
    struct.pack_into("<I", fadt, 0x24, physical_address)
    fadt[9] = (-sum(fadt)) & 0xFF
    fadt_path = directory / "FACP"
    fadt_path.write_bytes(fadt)

    facs = bytearray(64)
    facs[:4] = b"FACS"
    struct.pack_into("<I", facs, 4, len(facs))
    struct.pack_into("<I", facs, 8, 0x1234)
    struct.pack_into("<I", facs, 0x14, 0x1)
    facs[0x20] = 2
    facs_path = directory / "FACS"
    facs_path.write_bytes(facs)
    return fadt_path, facs_path


def test_facs_profile_exposes_static_vector_fields_without_current_values(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)

    profile = FacsProfileLoader(fadt_path, facs_path).load()
    facts = json.loads(JsonProfileWriter().render(profile))

    assert facts["source"] == "acpi_facs"
    assert facts["facs"] == {
        "physical_address": 0x3B7CA000,
        "length": 64,
        "signature": "FACS",
        "pointer_source": "FIRMWARE_CTRL",
        "fadt_pointers": {"firmware_ctrl": 0x3B7CA000, "x_firmware_ctrl": 0},
        "legacy_waking_vector": {"start": 0x3B7CA00C, "end": 0x3B7CA00F},
        "extended_waking_vector": {"start": 0x3B7CA018, "end": 0x3B7CA01F},
        "metadata": {"hardware_signature": 0x1234, "flags": 1, "version": 2},
        "collection_complete": True,
        "provenance": {"fadt_source": str(fadt_path), "facs_source": str(facs_path)},
    }


def test_facs_profile_prefers_extended_fadt_pointer(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    fadt = bytearray(fadt_path.read_bytes())
    struct.pack_into("<Q", fadt, 0x84, 0x100000000)
    fadt[9] = 0
    fadt[9] = (-sum(fadt)) & 0xFF
    fadt_path.write_bytes(fadt)

    profile = FacsProfileLoader(fadt_path, facs_path).load()

    assert profile.facs.physical_address == 0x100000000
    assert profile.facs.pointer_source == "X_FIRMWARE_CTRL"
    assert profile.facs.legacy_waking_vector.start == 0x10000000C


def test_facs_profile_rejects_invalid_fadt_signature(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    fadt_path.write_bytes(b"BAD!" + fadt_path.read_bytes()[4:])

    with pytest.raises(FacsProfileError, match="signature"):
        FacsProfileLoader(fadt_path, facs_path).load()


def test_facs_profile_rejects_invalid_fadt_checksum(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    fadt_path.write_bytes(fadt_path.read_bytes()[:-1] + b"\x01")

    with pytest.raises(FacsProfileError, match="checksum"):
        FacsProfileLoader(fadt_path, facs_path).load()


def test_facs_profile_rejects_truncated_facs(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    facs_path.write_bytes(facs_path.read_bytes()[:32])

    with pytest.raises(FacsProfileError, match="Truncated FACS"):
        FacsProfileLoader(fadt_path, facs_path).load()


def test_facs_profile_rejects_zero_fadt_pointer(tmp_path: Path) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path, physical_address=0)

    with pytest.raises(FacsProfileError, match="no usable FACS pointer"):
        FacsProfileLoader(fadt_path, facs_path).load()


def test_facs_profile_uses_sudo_for_root_only_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    runner = _AcpiTableRunner(
        {str(fadt_path): fadt_path.read_bytes(), str(facs_path): facs_path.read_bytes()}
    )
    monkeypatch.setattr(Path, "read_bytes", _deny_direct_table_read)

    profile = FacsProfileLoader(fadt_path, facs_path, runner).load()

    assert profile.facs.legacy_waking_vector.start == 0x3B7CA00C
    assert runner.specs == [
        CommandSpec(argv=["cat", str(fadt_path)], sudo=True, capture_output=True),
        CommandSpec(argv=["cat", str(facs_path)], sudo=True, capture_output=True),
    ]


def test_facs_profile_fails_when_sudo_cannot_read_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    monkeypatch.setattr(Path, "read_bytes", _deny_direct_table_read)

    with pytest.raises(FacsProfileError, match="Unable to read ACPI table"):
        FacsProfileLoader(fadt_path, facs_path, _FailingAcpiTableRunner()).load()


def test_facs_cli_reports_missing_table_instead_of_empty_profile(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("s3bootscript_analyzer.cli.DEFAULT_FADT_PATH", tmp_path / "missing-FACP")
    monkeypatch.setattr("s3bootscript_analyzer.cli.DEFAULT_FACS_PATH", tmp_path / "missing-FACS")

    exit_code = main(
        [
            "generate-profile",
            "--source",
            "facs",
        ]
    )

    assert exit_code == 1
    assert "Error:" in capsys.readouterr().out


def test_facs_cli_generates_profile_from_acpi_tables(
    tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fadt_path, facs_path = _acpi_tables(tmp_path)
    monkeypatch.setattr("s3bootscript_analyzer.cli.DEFAULT_FADT_PATH", fadt_path)
    monkeypatch.setattr("s3bootscript_analyzer.cli.DEFAULT_FACS_PATH", facs_path)

    exit_code = main(
        [
            "generate-profile",
            "--source",
            "facs",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["facs"]["legacy_waking_vector"]["start"] == (
        0x3B7CA00C
    )


@pytest.mark.parametrize("removed_option", ["--fadt-path", "--facs-path"])
def test_facs_cli_rejects_removed_table_path_options(removed_option: str) -> None:
    with pytest.raises(SystemExit, match="2"):
        build_parser().parse_args(["generate-profile", "--source", "facs", removed_option, "table"])
