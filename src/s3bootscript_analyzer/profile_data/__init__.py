"""Producer-specific profile generation and generic JSON profile loading."""

from __future__ import annotations

from s3bootscript_analyzer.profile_data.contracts import (
    ProfileLoader,
    ProfileWriter,
)
from s3bootscript_analyzer.profile_data.generator import GenerateProfile
from s3bootscript_analyzer.profile_data.json_loader import JsonProfileLoader, ProfileLoadError
from s3bootscript_analyzer.profile_data.kernel_iomem import (
    KERNEL_IOMEM_PATTERN,
    KernelProfileLoader,
)
from s3bootscript_analyzer.profile_data.models import (
    DEFAULT_SCHEMA_VERSION,
    PlatformProfile,
    ProfileDiagnostic,
    ProfileRange,
)
from s3bootscript_analyzer.profile_data.proc_iomem import ProcIomemProfileLoader
from s3bootscript_analyzer.profile_data.writers import JsonProfileWriter

__all__ = [
    "DEFAULT_SCHEMA_VERSION",
    "GenerateProfile",
    "JsonProfileWriter",
    "JsonProfileLoader",
    "KERNEL_IOMEM_PATTERN",
    "KernelProfileLoader",
    "PlatformProfile",
    "ProcIomemProfileLoader",
    "ProfileDiagnostic",
    "ProfileLoader",
    "ProfileLoadError",
    "ProfileRange",
    "ProfileWriter",
]
