"""Load producer JSON directly as generic analysis facts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Never

from s3bootscript_analyzer.analysis.contracts import AnalysisProfileLoader
from s3bootscript_analyzer.analysis.models import ProfileSelection
from s3bootscript_analyzer.analysis.profile import AnalysisProfile
from s3bootscript_analyzer.errors import BootScriptAnalyzerError


class ProfileLoadError(BootScriptAnalyzerError):
    """Raised when an explicitly selected profile cannot be loaded."""


class JsonProfileLoader(AnalysisProfileLoader):
    """Load a JSON object or supply an empty default when no path is selected."""

    def load(self, selection: ProfileSelection) -> AnalysisProfile:
        """Preserve producer fields without classification or schema translation."""
        if selection.path is None:
            return AnalysisProfile(name="default", data={})
        try:
            return _load_profile(selection.path)
        except (OSError, ValueError, RecursionError) as ex:
            raise ProfileLoadError(f"Unable to load profile '{selection.path}': {ex}") from ex


def _load_profile(path: Path) -> AnalysisProfile:
    value: object = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("Profile must be a JSON object")
    return AnalysisProfile(name=path.name, data=value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate profile key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Never:
    raise ValueError(f"Invalid JSON constant: {value}")
