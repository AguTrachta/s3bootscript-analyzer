"""Profile generation data models."""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ProfileRange:
    """Address range discovered from a platform data source."""

    name: str
    start: int
    end: int
    source_label: str


@dataclass(frozen=True)
class ProfileRanges:
    """Grouped profile address ranges."""

    os_controlled: list[ProfileRange] = field(default_factory=list)
    firmware_related: list[ProfileRange] = field(default_factory=list)
    mmio_related: list[ProfileRange] = field(default_factory=list)
    unknown: list[ProfileRange] = field(default_factory=list)


@dataclass(frozen=True)
class ProfileDiagnostic:
    """Diagnostic emitted while generating a profile."""

    level: str
    message: str


@dataclass(frozen=True)
class PlatformProfile:
    """Generated platform profile used by later analysis stages."""

    source: str
    ranges: ProfileRanges
    diagnostics: list[ProfileDiagnostic] = field(default_factory=list)
    schema_version: int = DEFAULT_SCHEMA_VERSION
