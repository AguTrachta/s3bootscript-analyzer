"""Kernel-only profile parsing from Linux /proc/iomem text."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from re import Match

from s3bootscript_analyzer.profile_data.commands import CommandSpec, SubprocessRunner
from s3bootscript_analyzer.profile_data.contracts import ProfileLoader
from s3bootscript_analyzer.profile_data.models import (
    PlatformProfile,
    ProfileDiagnostic,
    ProfileRange,
    ProfileRanges,
)

_NAME_MAP = {
    "Kernel code": "KERNEL_CODE_RANGE",
    "Kernel data": "KERNEL_DATA_RANGE",
    "Kernel bss": "KERNEL_BSS_RANGE",
    "Kernel rodata": "KERNEL_RODATA_RANGE",
}

PROC_IOMEM_PATH = Path("/proc/iomem")
KERNEL_IOMEM_PATTERN = r"Kernel code|Kernel data|Kernel bss|Kernel rodata"
KERNEL_IOMEM_SOURCE = "proc_iomem_kernel"
WARNING_LEVEL = "warning"
IOMEM_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+?)\s*$")


@dataclass(frozen=True)
class KernelProfileLoader(ProfileLoader):
    """Parse kernel-specific procfs iomem text into a platform profile."""

    runner: SubprocessRunner
    source_path: Path = PROC_IOMEM_PATH
    pattern: str = KERNEL_IOMEM_PATTERN

    def load(self) -> PlatformProfile:
        raw_text = self._read()
        ranges, diagnostics = _parse_kernel_ranges(raw_text)
        return PlatformProfile(
            source=KERNEL_IOMEM_SOURCE,
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


def _parse_kernel_ranges(raw_text: str) -> tuple[ProfileRanges, list[ProfileDiagnostic]]:
    ranges = ProfileRanges()
    diagnostics: list[ProfileDiagnostic] = []

    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        _parse_kernel_line(line_number, line, ranges, diagnostics)

    if not raw_text.strip() or not ranges.os_controlled:
        diagnostics.append(
            ProfileDiagnostic(
                level=WARNING_LEVEL,
                message="/proc/iomem kernel source did not contain matching ranges",
            )
        )

    return ranges, diagnostics


def _parse_kernel_line(
    line_number: int,
    line: str,
    ranges: ProfileRanges,
    diagnostics: list[ProfileDiagnostic],
) -> None:
    if not line.strip():
        return
    match = IOMEM_RANGE_RE.match(line)
    if match is None:
        diagnostics.append(_malformed_line_diagnostic(line_number, line))
        return

    profile_range = _profile_range_from_match(match)
    if profile_range is None:
        return
    if profile_range.start > profile_range.end:
        diagnostics.append(_invalid_range_diagnostic(line_number, line))
        return

    ranges.os_controlled.append(profile_range)


def _profile_range_from_match(match: Match[str]) -> ProfileRange | None:
    start_text, end_text, source_label = match.groups()
    mapped_name = _NAME_MAP.get(source_label)
    if mapped_name is None:
        return None

    return ProfileRange(
        name=mapped_name,
        start=int(start_text, 16),
        end=int(end_text, 16),
        source_label=source_label,
    )


def _malformed_line_diagnostic(line_number: int, line: str) -> ProfileDiagnostic:
    return ProfileDiagnostic(
        level=WARNING_LEVEL,
        message=f"Skipped malformed /proc/iomem kernel line {line_number}: {line}",
    )


def _invalid_range_diagnostic(line_number: int, line: str) -> ProfileDiagnostic:
    return ProfileDiagnostic(
        level=WARNING_LEVEL,
        message=f"Skipped invalid /proc/iomem kernel range at line {line_number}: {line}",
    )
