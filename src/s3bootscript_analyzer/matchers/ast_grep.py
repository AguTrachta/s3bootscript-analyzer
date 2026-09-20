"""Run ast-grep and normalize its JSON stream into typed analysis candidates."""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

import yaml

from s3bootscript_analyzer.analysis.contracts import RuleExecutionError
from s3bootscript_analyzer.analysis.models import MatchEvidence
from s3bootscript_analyzer.errors import BootScriptAnalyzerError
from s3bootscript_analyzer.ir.contracts import SemanticDocument
from s3bootscript_analyzer.plugins.s3 import _S3Matcher

DECIMAL_PATTERN = re.compile(r"^-?[0-9]+$")
HEX_PATTERN = re.compile(r"^0[xX][0-9a-fA-F]+$")


class AstGrepOutputError(BootScriptAnalyzerError, ValueError):
    """Raised when ast-grep emits an invalid JSON stream record."""


class AstGrepMatcher(_S3Matcher):
    """Execute native rules through a trusted ast-grep backend."""

    matcher_type = "ast_grep"

    def __init__(self, executable: Path, config_path: Path, timeout_seconds: float = 10.0) -> None:
        self._executable = executable
        self._config_path = config_path
        self._timeout_seconds = timeout_seconds
        self._decoder = AstGrepJsonDecoder()

    def match(
        self, document: SemanticDocument, config: Mapping[str, object]
    ) -> tuple[MatchEvidence, ...]:
        """Return source-mapped evidence or a rule-scoped execution failure."""
        result = self._run(document.text, config)
        _ensure_success(result)
        try:
            return self._decoder.decode_stream(result.stdout.splitlines(), document)
        except AstGrepOutputError as ex:
            raise RuleExecutionError(str(ex)) from ex

    def _run(self, text: str, config: Mapping[str, object]) -> subprocess.CompletedProcess[str]:
        # Native severity controls backend exit status, not the analysis finding severity.
        native_rule = yaml.safe_dump({**config, "id": "s3-match", "severity": "hint"})
        try:
            # Executable/config are trusted constructor inputs; no shell is invoked.
            return subprocess.run(  # nosec B603
                [
                    str(self._executable),
                    "scan",
                    "--config",
                    str(self._config_path),
                    "--inline-rules",
                    native_rule,
                    "--stdin",
                    "--json=stream",
                ],
                input=text,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as ex:
            raise RuleExecutionError(f"ast-grep execution failed: {ex}") from ex


def _ensure_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise RuleExecutionError(
            f"ast-grep exited with status {result.returncode}: {result.stderr.strip()}"
        )


class AstGrepJsonDecoder:
    """Decode JSON-stream matches without leaking backend dictionaries."""

    def decode_stream(
        self,
        lines: Iterable[str],
        document: SemanticDocument,
    ) -> tuple[MatchEvidence, ...]:
        """Decode non-blank records in backend output order."""
        candidates: list[MatchEvidence] = []
        for line in lines:
            if line.strip():
                candidates.append(self._decode_line(line, document))
        return tuple(candidates)

    def _decode_line(self, line: str, document: SemanticDocument) -> MatchEvidence:
        try:
            payload = _mapping(json.loads(line), "ast-grep record")
            return _candidate(payload, document)
        except (IndexError, json.JSONDecodeError, KeyError, TypeError, ValueError) as ex:
            raise AstGrepOutputError(f"Invalid ast-grep JSON record: {ex}") from ex


def _candidate(payload: Mapping[str, object], document: SemanticDocument) -> MatchEvidence:
    semantic_text = _text(payload["text"], "text")
    semantic_line = _semantic_line(payload["range"])
    source = document.source_for_line(semantic_line)
    return MatchEvidence(
        bindings=_bindings(payload.get("metaVariables", {})),
        semantic_text=semantic_text,
        semantic_line=semantic_line,
        record_index=source.record_index,
        opcode_offset=source.opcode_offset,
    )


def _semantic_line(value: object) -> int:
    match_range = _mapping(value, "range")
    start = _mapping(match_range["start"], "range.start")
    zero_based_line = _integer(start["line"], "range.start.line")
    return zero_based_line + 1


def _bindings(value: object) -> dict[str, bool | float | int | str]:
    meta_variables = _mapping(value, "metaVariables")
    single = _mapping(meta_variables.get("single", {}), "metaVariables.single")
    multi = _mapping(meta_variables.get("multi", {}), "metaVariables.multi")
    bindings = {name: _capture_value(capture) for name, capture in single.items()}
    bindings.update(_multi_bindings(multi))
    return bindings


def _multi_bindings(
    captures: Mapping[str, object],
) -> dict[str, bool | float | int | str]:
    bindings: dict[str, bool | float | int | str] = {}
    for name, raw_values in captures.items():
        for index, capture in enumerate(_list(raw_values, f"multi capture {name}")):
            bindings[f"{name}_{index}"] = _capture_value(capture)
    return bindings


def _capture_value(value: object) -> bool | float | int | str:
    capture = _mapping(value, "capture")
    text = _text(capture["text"], "capture.text")
    if HEX_PATTERN.fullmatch(text):
        return int(text, 16)
    if DECIMAL_PATTERN.fullmatch(text):
        return int(text, 10)
    return text


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{label} must be a mapping with string keys")
    return cast(Mapping[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    return value
