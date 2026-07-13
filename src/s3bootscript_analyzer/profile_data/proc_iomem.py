"""Linux /proc/iomem profile source scaffolding."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from s3bootscript_analyzer.profile_data.commands import CommandSpec, SubprocessRunner
from s3bootscript_analyzer.profile_data.contracts import ProfileLoader
from s3bootscript_analyzer.profile_data.models import (
    PlatformProfile,
    ProfileDiagnostic,
    ProfileRange,
)

PROC_IOMEM_PATH = Path("/proc/iomem")
IOMEM_PROFILE_PATTERN = r"Kernel|ACPI|reserved|System RAM|PCI Bus"
IOMEM_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+?)\s*$")
PROC_IOMEM_SOURCE = "proc_iomem"
WARNING_LEVEL = "warning"
NumberedLine = tuple[int, str]


@dataclass(frozen=True)
class ProcIomemProfileLoader(ProfileLoader):
    """Load a platform profile from the Linux /proc/iomem interface."""

    runner: SubprocessRunner
    source_path: Path = PROC_IOMEM_PATH
    pattern: str = IOMEM_PROFILE_PATTERN

    def load(self) -> PlatformProfile:
        raw_text = self._read()
        ranges, diagnostics = _parse_iomem_ranges(raw_text)
        return PlatformProfile(
            source=PROC_IOMEM_SOURCE,
            ranges=ranges,
            diagnostics=diagnostics,
        )

    def _read(self) -> str:
        proc = self.runner.run(
            CommandSpec(
                argv=["grep", "-Ei", self.pattern, str(self.source_path)],
                capture_output=True,
                sudo=True,
                allowed_return_codes=(0, 1),  # grep returns 1 if no matches found
            )
        )
        return (proc.stdout or b"").decode("utf-8", errors="ignore")


def _parse_iomem_ranges(raw_text: str) -> tuple[list[ProfileRange], list[ProfileDiagnostic]]:
    ranges: list[ProfileRange] = []
    diagnostics: list[ProfileDiagnostic] = []

    for numbered_line in enumerate(raw_text.splitlines(), start=1):
        _parse_iomem_line(numbered_line, ranges, diagnostics)

    if not raw_text.strip():
        diagnostics.append(
            ProfileDiagnostic(
                level=WARNING_LEVEL,
                message="/proc/iomem source did not contain matching ranges",
            )
        )

    return ranges, diagnostics


def _parse_iomem_line(
    numbered_line: NumberedLine,
    ranges: list[ProfileRange],
    diagnostics: list[ProfileDiagnostic],
) -> None:
    line_number, line = numbered_line
    if not line.strip():
        return
    profile_range = _parse_profile_range(line)
    if profile_range is None:
        diagnostics.append(_malformed_line_diagnostic(line_number, line))
        return
    if profile_range.start > profile_range.end:
        diagnostics.append(_invalid_range_diagnostic(line_number, line))
        return
    ranges.append(profile_range)


def _parse_profile_range(line: str) -> ProfileRange | None:
    match = IOMEM_RANGE_RE.match(line)
    if match is None:
        return None
    start_text, end_text, label = match.groups()
    return ProfileRange(
        name=label,
        start=int(start_text, 16),
        end=int(end_text, 16),
        source_label=label,
    )


def _malformed_line_diagnostic(line_number: int, line: str) -> ProfileDiagnostic:
    return ProfileDiagnostic(
        level=WARNING_LEVEL,
        message=f"Skipped malformed /proc/iomem line {line_number}: {line}",
    )


def _invalid_range_diagnostic(line_number: int, line: str) -> ProfileDiagnostic:
    return ProfileDiagnostic(
        level=WARNING_LEVEL,
        message=f"Skipped invalid /proc/iomem range at line {line_number}: {line}",
    )
