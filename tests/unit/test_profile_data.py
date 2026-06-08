import json
import subprocess
import sys
from pathlib import Path

import pytest

from s3bootscript_analyzer.profile_data import (
    DEFAULT_SCHEMA_VERSION,
    GenerateProfile,
    JsonProfileWriter,
    KernelIomemParser,
    PlatformProfile,
    ProcIomemParser,
    ProcIomemReader,
    ProfileDiagnostic,
    ProfileParser,
    ProfileRange,
    ProfileRanges,
    ProfileSourceReader,
    ProfileWriter,
)
from s3bootscript_analyzer.profile_data.commands import CommandSpec, SubprocessRunner


class StaticProfileReader(ProfileSourceReader):
    def read(self) -> str:
        return "raw profile source"


class StaticProfileParser(ProfileParser):
    def parse(self, raw_text: str) -> PlatformProfile:
        assert raw_text == "raw profile source"
        return PlatformProfile(source="test", ranges=ProfileRanges())


class CapturingProfileWriter(ProfileWriter):
    def __init__(self) -> None:
        self.profile: PlatformProfile | None = None
        self.output_path: Path | None = None

    def write(self, profile: PlatformProfile, output_path: Path) -> None:
        self.profile = profile
        self.output_path = output_path


def test_platform_profile_uses_default_schema_version() -> None:
    profile = PlatformProfile(source="test", ranges=ProfileRanges())

    assert profile.schema_version == DEFAULT_SCHEMA_VERSION


def test_generate_profile_coordinates_reader_parser_and_writer(tmp_path: Path) -> None:
    output_path = tmp_path / "profile.json"
    writer = CapturingProfileWriter()
    generator = GenerateProfile(
        output_path=output_path,
        reader=StaticProfileReader(),
        parser=StaticProfileParser(),
        writer=writer,
    )

    generator.run()

    assert writer.profile == PlatformProfile(source="test", ranges=ProfileRanges())
    assert writer.output_path == output_path


def test_subprocess_runner_returns_completed_process() -> None:
    result = SubprocessRunner().run(
        CommandSpec(
            argv=[sys.executable, "-c", "print('profile')"],
            capture_output=True,
        )
    )

    assert result.returncode == 0
    assert result.stdout == b"profile\n"


def test_subprocess_runner_rejects_unexpected_return_code() -> None:
    with pytest.raises(subprocess.CalledProcessError):
        SubprocessRunner().run(
            CommandSpec(
                argv=[sys.executable, "-c", "raise SystemExit(3)"],
                capture_output=True,
            )
        )


def test_proc_iomem_reader_runs_grep_and_decodes_stdout() -> None:
    runner = CapturingRunner(stdout=b"00000000-00000fff : System RAM\n")
    reader = ProcIomemReader(runner=runner, source_path=Path("/tmp/iomem"))

    assert reader.read() == "00000000-00000fff : System RAM\n"
    assert runner.spec is not None
    assert runner.spec.argv == ["grep", "-Ei", reader.pattern, "/tmp/iomem"]
    assert runner.spec.capture_output is True
    assert runner.spec.allowed_return_codes == (0, 1)


def test_proc_iomem_reader_returns_empty_text_when_grep_finds_no_matches() -> None:
    reader = ProcIomemReader(runner=CapturingRunner(returncode=1, stdout=b""))

    assert reader.read() == ""


def test_proc_iomem_parser_groups_known_ranges_and_unknown_ranges() -> None:
    profile = ProcIomemParser().parse(
        "\n".join(
            [
                "00001000-00001fff : System RAM",
                "  00002000-00002fff : Kernel code",
                "00003000-00003fff : ACPI Tables",
                "00004000-00004fff : PCI Bus 0000:00",
                "00005000-00005fff : Crash kernel",
            ]
        )
    )

    assert profile.source == "proc_iomem"
    assert profile.ranges.os_controlled == [
        ProfileRange("System RAM", 0x1000, 0x1FFF, "System RAM"),
        ProfileRange("Kernel code", 0x2000, 0x2FFF, "Kernel code"),
    ]
    assert profile.ranges.firmware_related == [
        ProfileRange("ACPI Tables", 0x3000, 0x3FFF, "ACPI Tables")
    ]
    assert profile.ranges.mmio_related == [
        ProfileRange("PCI Bus 0000:00", 0x4000, 0x4FFF, "PCI Bus 0000:00")
    ]
    assert profile.ranges.unknown == [ProfileRange("Crash kernel", 0x5000, 0x5FFF, "Crash kernel")]
    assert not profile.diagnostics


def test_proc_iomem_parser_reports_malformed_and_invalid_ranges() -> None:
    profile = ProcIomemParser().parse(
        "\n".join(
            [
                "not a range",
                "00002000-00001000 : System RAM",
            ]
        )
    )

    assert profile.ranges == ProfileRanges()
    assert profile.diagnostics == [
        ProfileDiagnostic("warning", "Skipped malformed /proc/iomem line 1: not a range"),
        ProfileDiagnostic(
            "warning",
            "Skipped invalid /proc/iomem range at line 2: 00002000-00001000 : System RAM",
        ),
    ]


def test_proc_iomem_parser_reports_empty_matching_source() -> None:
    profile = ProcIomemParser().parse("")

    assert profile.ranges == ProfileRanges()
    assert profile.diagnostics == [
        ProfileDiagnostic("warning", "/proc/iomem source did not contain matching ranges")
    ]


def test_kernel_iomem_parser_maps_kernel_labels_to_profile_names() -> None:
    profile = KernelIomemParser().parse(
        "\n".join(
            [
                "00001000-00001fff : Kernel code",
                "00002000-00002fff : Kernel data",
                "00003000-00003fff : Kernel bss",
                "00004000-00004fff : Kernel rodata",
                "00005000-00005fff : System RAM",
            ]
        )
    )

    assert profile.source == "proc_iomem_kernel"
    assert profile.ranges.os_controlled == [
        ProfileRange("KERNEL_CODE_RANGE", 0x1000, 0x1FFF, "Kernel code"),
        ProfileRange("KERNEL_DATA_RANGE", 0x2000, 0x2FFF, "Kernel data"),
        ProfileRange("KERNEL_BSS_RANGE", 0x3000, 0x3FFF, "Kernel bss"),
        ProfileRange("KERNEL_RODATA_RANGE", 0x4000, 0x4FFF, "Kernel rodata"),
    ]
    assert not profile.ranges.firmware_related
    assert not profile.ranges.mmio_related
    assert not profile.ranges.unknown
    assert not profile.diagnostics


def test_kernel_iomem_parser_reports_malformed_and_invalid_ranges() -> None:
    profile = KernelIomemParser().parse(
        "\n".join(
            [
                "not a range",
                "00002000-00001000 : Kernel code",
            ]
        )
    )

    assert profile.ranges == ProfileRanges()
    assert profile.diagnostics == [
        ProfileDiagnostic("warning", "Skipped malformed /proc/iomem kernel line 1: not a range"),
        ProfileDiagnostic(
            "warning",
            "Skipped invalid /proc/iomem kernel range at line 2: 00002000-00001000 : Kernel code",
        ),
        ProfileDiagnostic(
            "warning",
            "/proc/iomem kernel source did not contain matching ranges",
        ),
    ]


def test_kernel_iomem_parser_reports_empty_or_non_matching_source() -> None:
    profile = KernelIomemParser().parse("00001000-00001fff : System RAM")

    assert profile.ranges == ProfileRanges()
    assert profile.diagnostics == [
        ProfileDiagnostic(
            "warning",
            "/proc/iomem kernel source did not contain matching ranges",
        )
    ]


def test_json_profile_writer_writes_profile_json(tmp_path: Path) -> None:
    output_path = tmp_path / "profile.json"
    profile = PlatformProfile(
        source="proc_iomem",
        ranges=ProfileRanges(
            os_controlled=[ProfileRange("System RAM", 0x1000, 0x1FFF, "System RAM")]
        ),
    )

    JsonProfileWriter().write(profile, output_path)

    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "source": "proc_iomem",
        "ranges": {
            "os_controlled": [
                {
                    "name": "System RAM",
                    "start": 4096,
                    "end": 8191,
                    "source_label": "System RAM",
                }
            ],
            "firmware_related": [],
            "mmio_related": [],
            "unknown": [],
        },
        "diagnostics": [],
        "schema_version": DEFAULT_SCHEMA_VERSION,
    }


class CapturingRunner(SubprocessRunner):
    def __init__(self, returncode: int = 0, stdout: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.spec: CommandSpec | None = None

    def run(self, spec: CommandSpec) -> subprocess.CompletedProcess[bytes]:
        self.spec = spec
        return subprocess.CompletedProcess(
            args=list(spec.argv),
            returncode=self.returncode,
            stdout=self.stdout,
            stderr=b"",
        )
