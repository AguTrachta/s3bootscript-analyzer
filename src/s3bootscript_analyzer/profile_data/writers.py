"""Profile writer scaffolding."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from s3bootscript_analyzer.errors import OutputWriteError
from s3bootscript_analyzer.profile_data.contracts import ProfileWriter
from s3bootscript_analyzer.profile_data.models import PlatformProfile

JSON_INDENT = 2
TRAILING_LINE_SEPARATOR = "\n"


class JsonProfileWriter(ProfileWriter):
    """Write a platform profile as JSON."""

    def write(self, profile: PlatformProfile, output_path: Path) -> None:
        try:
            output_path.write_text(self.render(profile), encoding="utf-8")
        except OSError as ex:
            raise OutputWriteError(f"Unable to write profile JSON '{output_path}': {ex}") from ex

    def render(self, profile: PlatformProfile) -> str:
        """Render a platform profile as formatted JSON text."""
        return render_profile_json(profile)


def render_profile_json(profile: PlatformProfile) -> str:
    """Render a platform profile as formatted JSON text."""
    return json.dumps(asdict(profile), indent=JSON_INDENT) + TRAILING_LINE_SEPARATOR
