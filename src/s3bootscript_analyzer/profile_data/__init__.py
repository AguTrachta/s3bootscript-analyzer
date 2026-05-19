"""Profile generation scaffolding."""

from __future__ import annotations

from s3bootscript_analyzer.profile_data.contracts import (
    ProfileParser,
    ProfileSourceReader,
    ProfileWriter,
)
from s3bootscript_analyzer.profile_data.generator import GenerateProfile
from s3bootscript_analyzer.profile_data.models import (
    DEFAULT_SCHEMA_VERSION,
    PlatformProfile,
    ProfileDiagnostic,
    ProfileRange,
    ProfileRanges,
)
from s3bootscript_analyzer.profile_data.proc_iomem import ProcIomemParser, ProcIomemReader
from s3bootscript_analyzer.profile_data.writers import JsonProfileWriter

__all__ = [
    "DEFAULT_SCHEMA_VERSION",
    "GenerateProfile",
    "JsonProfileWriter",
    "PlatformProfile",
    "ProcIomemParser",
    "ProcIomemReader",
    "ProfileDiagnostic",
    "ProfileParser",
    "ProfileRange",
    "ProfileRanges",
    "ProfileSourceReader",
    "ProfileWriter",
]
