"""Immutable values used by analysis orchestration and rule evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar

from s3bootscript_analyzer.analysis.profile import JsonObject, freeze_json_object

type BindingValue = bool | float | int | str
type BindingSet = Mapping[str, BindingValue]
type MatcherConfig = Mapping[str, object]


class Severity(StrEnum):
    """Severity assigned by a declarative rule."""

    SAFE = "safe"
    INFORMATIONAL = "informational"
    WARNING = "warning"
    CRITICAL = "critical"


class EvaluationOutcome(StrEnum):
    """Result of evaluating one rule independently from severity."""

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class RuleDefinition:
    """Validated declarative rule consumed by the analysis engine."""

    schema_version: ClassVar[int] = 1
    rule_id: str
    plugin_id: str
    title: str
    description: str
    severity: Severity
    enabled: bool
    required_fields: tuple[str, ...]
    matcher_type: str
    matcher_config: MatcherConfig
    condition: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "matcher_config", MappingProxyType(dict(self.matcher_config)))


@dataclass(frozen=True)
class MatchEvidence:
    """One plugin match with condition bindings and binary traceability."""

    bindings: BindingSet
    semantic_text: str
    semantic_line: int
    record_index: int
    opcode_offset: int
    record: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bindings", MappingProxyType(dict(self.bindings)))
        object.__setattr__(self, "record", freeze_json_object(self.record))


@dataclass(frozen=True)
class Diagnostic:
    """Structured problem that can be reported without losing other results."""

    code: str
    message: str
    source: str | None = None


@dataclass(frozen=True)
class RuleEvaluation:
    """Complete evaluation of one rule."""

    rule: RuleDefinition
    outcome: EvaluationOutcome
    evidence: tuple[MatchEvidence, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True)
class AnalysisReport:
    """Application result containing all context required for reporting."""

    artifact_name: str
    plugin_id: str
    profile_name: str
    evaluations: tuple[RuleEvaluation, ...]
    diagnostics: tuple[Diagnostic, ...] = ()


@dataclass(frozen=True)
class ProfileSelection:
    """Explicit profile path or a request for the configured default profile."""

    path: Path | None = None
