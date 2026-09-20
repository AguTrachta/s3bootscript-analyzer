"""Safe YAML loading and strict mapping into reduced rule definitions."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast

import yaml

from s3bootscript_analyzer.analysis.models import Diagnostic, RuleDefinition, Severity
from s3bootscript_analyzer.extensions import AnalysisPlugin
from s3bootscript_analyzer.rules.models import RuleLoadResult, RuleSource

SUPPORTED_SCHEMA_VERSION = 1
MAX_RULE_SOURCE_CHARS = 1_000_000
IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
TOP_LEVEL_FIELDS = frozenset(
    {"condition", "matcher", "metadata", "plugin", "profile", "schema_version"}
)
REQUIRED_TOP_LEVEL_FIELDS = frozenset({"matcher", "metadata", "plugin", "schema_version"})
METADATA_FIELDS = frozenset({"description", "enabled", "id", "severity", "title"})
REQUIRED_METADATA_FIELDS = frozenset({"id", "severity", "title"})
PROFILE_FIELDS = frozenset({"required_fields"})
MATCHER_FIELDS = frozenset({"config", "type"})
CONDITION_FIELDS = frozenset({"expression", "language"})


class YamlRuleLoader:
    """Load analyzer rule fields while preserving native matcher configuration."""

    def load(
        self,
        sources: Sequence[RuleSource],
        plugin: AnalysisPlugin,
    ) -> RuleLoadResult:
        """Load valid rules while preserving diagnostics for invalid sources."""
        accumulator = _LoadAccumulator()
        for source in sources:
            accumulator.add(source, self._load_source(source, plugin))
        return accumulator.result()

    def _load_source(self, source: RuleSource, plugin: AnalysisPlugin) -> _SourceLoad:
        if len(source.text) > MAX_RULE_SOURCE_CHARS:
            diagnostic = _diagnostic(
                source,
                "rule_source_too_large",
                "Rule source exceeds the configured size limit",
            )
            return _SourceLoad(diagnostics=[diagnostic])
        try:
            documents = tuple(yaml.safe_load_all(source.text))
        except yaml.YAMLError as ex:
            diagnostic = _diagnostic(source, "invalid_yaml", f"Invalid YAML: {ex}")
            return _SourceLoad(diagnostics=[diagnostic])
        return self._load_documents(source, documents, plugin)

    def _load_documents(
        self,
        source: RuleSource,
        documents: tuple[object, ...],
        plugin: AnalysisPlugin,
    ) -> _SourceLoad:
        result = _SourceLoad()
        for document in documents:
            self._load_document(source, document, plugin, result)
        return result

    def _load_document(
        self,
        source: RuleSource,
        document: object,
        plugin: AnalysisPlugin,
        result: _SourceLoad,
    ) -> None:
        try:
            result.rules.append(_map_rule(document, plugin))
        except (LookupError, TypeError, ValueError) as ex:
            result.diagnostics.append(_diagnostic(source, "invalid_rule", str(ex)))


@dataclass
class _SourceLoad:
    rules: list[RuleDefinition] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass
class _LoadAccumulator:
    rules: list[RuleDefinition] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    rule_ids: set[str] = field(default_factory=set)

    def add(self, source: RuleSource, source_load: _SourceLoad) -> None:
        self.diagnostics.extend(source_load.diagnostics)
        for rule in source_load.rules:
            self._add_rule(source, rule)

    def result(self) -> RuleLoadResult:
        return RuleLoadResult(tuple(self.rules), tuple(self.diagnostics))

    def _add_rule(self, source: RuleSource, rule: RuleDefinition) -> None:
        if rule.rule_id in self.rule_ids:
            diagnostic = _diagnostic(
                source,
                "duplicate_rule_id",
                f"Duplicate rule id: {rule.rule_id}",
            )
            self.diagnostics.append(diagnostic)
            return
        self.rules.append(rule)
        self.rule_ids.add(rule.rule_id)


def _map_rule(document: object, plugin: AnalysisPlugin) -> RuleDefinition:
    data = _mapping(document, "rule document")
    _validate_fields(data, TOP_LEVEL_FIELDS, REQUIRED_TOP_LEVEL_FIELDS, "rule document")
    plugin_id = _identifier(data["plugin"], "plugin")
    _ensure_compatible_plugin(plugin_id, plugin)
    metadata = _metadata(data["metadata"])
    matcher = _matcher(data["matcher"])
    _schema_version(data["schema_version"])
    return RuleDefinition(
        rule_id=_text(metadata["id"], "metadata.id"),
        plugin_id=plugin_id,
        title=_text(metadata["title"], "metadata.title"),
        description=_optional_text(metadata.get("description"), "metadata.description"),
        severity=_severity(metadata["severity"]),
        enabled=_optional_bool(metadata.get("enabled"), default=True),
        required_fields=_profile_requirements(data.get("profile")),
        matcher_type=matcher[0],
        matcher_config=matcher[1],
        condition=_condition(data.get("condition")),
    )


def _ensure_compatible_plugin(plugin_id: str, plugin: AnalysisPlugin) -> None:
    if plugin_id != plugin.plugin_id:
        message = f"Rule plugin {plugin_id} does not match selected plugin {plugin.plugin_id}"
        raise ValueError(message)


def _metadata(value: object) -> Mapping[str, object]:
    data = _mapping(value, "metadata")
    _validate_fields(data, METADATA_FIELDS, REQUIRED_METADATA_FIELDS, "metadata")
    return data


def _matcher(value: object) -> tuple[str, Mapping[str, object]]:
    data = _mapping(value, "matcher")
    _validate_fields(data, MATCHER_FIELDS, MATCHER_FIELDS, "matcher")
    matcher_type = _identifier(data["type"], "matcher type")
    config = _mapping(data["config"], "matcher config")
    return matcher_type, config


def _schema_version(value: object) -> int:
    if not _is_integer(value) or value != SUPPORTED_SCHEMA_VERSION:
        raise ValueError(f"Unsupported rule schema version: {value}")
    return value


def _profile_requirements(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    data = _mapping(value, "profile")
    _validate_fields(data, PROFILE_FIELDS, frozenset(), "profile")
    return _string_tuple(data.get("required_fields", []))


def _condition(value: object) -> str | None:
    if value is None:
        return None
    data = _mapping(value, "condition")
    _validate_fields(data, CONDITION_FIELDS, CONDITION_FIELDS, "condition")
    language = _text(data["language"], "condition.language")
    if language != "simpleeval":
        raise ValueError(f"Unsupported condition language: {language}")
    return _text(data["expression"], "condition.expression")


def _validate_fields(
    data: Mapping[str, object],
    allowed: frozenset[str],
    required: frozenset[str],
    section: str,
) -> None:
    unknown = sorted(set(data) - allowed)
    missing = sorted(required - set(data))
    if unknown:
        raise ValueError(f"Unknown {section} fields: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"Missing {section} fields: {', '.join(missing)}")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{label} must be a mapping with string keys")
    return cast(Mapping[str, object], value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{label} must be a non-empty string")
    return value


def _optional_text(value: object, label: str) -> str:
    if value is None:
        return ""
    return _text(value, label)


def _optional_bool(value: object, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise TypeError("metadata.enabled must be a boolean")
    return value


def _severity(value: object) -> Severity:
    try:
        return Severity(_text(value, "metadata.severity").lower())
    except ValueError as ex:
        raise ValueError(f"Unsupported rule severity: {value}") from ex


def _identifier(value: object, label: str) -> str:
    identifier = _text(value, label)
    if IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise ValueError(f"Invalid {label}: {identifier}")
    return identifier


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError("profile.required_fields must be a list of non-empty strings")
    return tuple(_text(item, "profile.required_fields entry") for item in value)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _diagnostic(source: RuleSource, code: str, message: str) -> Diagnostic:
    return Diagnostic(code=code, message=message, source=source.name)
