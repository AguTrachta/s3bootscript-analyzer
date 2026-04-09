"""Minimal application scaffolding for the analyzer package."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApplicationInfo:
    """Static metadata exposed by the initial scaffold."""

    name: str = "s3bootscript-analyzer"
    status: str = "scaffold-ready"


def get_application_info() -> ApplicationInfo:
    """Return basic package metadata for early integration checks."""

    return ApplicationInfo()
