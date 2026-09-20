"""Executable contract for loading untrusted declarative rule YAML."""

from collections.abc import Iterable

import pytest

from s3bootscript_analyzer.analysis import Diagnostic, MatchEvidence, RuleDefinition, Severity
from s3bootscript_analyzer.extensions import AnalysisDocument, AnalysisPlugin
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.rules import RuleSource, YamlRuleLoader

VALID_RULE = """\
schema_version: 1
plugin: s3bootscript
metadata:
  id: S3-DISPATCH-001
  title: Dispatch outside trusted execution memory
  description: Detect an untrusted S3 dispatch entry point.
  severity: critical
  enabled: true
profile:
  required_fields:
    - trusted_execution
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: call $ENTRY
condition:
  language: simpleeval
  expression: >-
    not any([ENTRY >= region["start"] and ENTRY <= region["end"]
             for region in profile["trusted_execution"]])
"""


class StaticDocument(AnalysisDocument):
    plugin_id = "s3bootscript"
    diagnostics: tuple[Diagnostic, ...] = ()


class AcceptingPlugin(AnalysisPlugin):
    plugin_id = "s3bootscript"

    def decode(self, _source: BinarySource) -> StaticDocument:
        return StaticDocument()

    def match(
        self,
        _document: AnalysisDocument,
        _rule: RuleDefinition,
    ) -> Iterable[MatchEvidence]:
        return ()


def test_loader_maps_valid_yaml_to_a_typed_rule() -> None:
    plugin = AcceptingPlugin()

    result = YamlRuleLoader().load([_source("dispatch.rule.yaml", VALID_RULE)], plugin)

    assert not result.diagnostics
    assert len(result.rules) == 1
    rule = result.rules[0]
    assert rule.schema_version == 1
    assert rule.plugin_id == "s3bootscript"
    assert rule.rule_id == "S3-DISPATCH-001"
    assert rule.severity is Severity.CRITICAL
    assert rule.enabled is True
    assert rule.required_fields == ("trusted_execution",)
    assert rule.matcher_type == "ast_grep"
    assert rule.matcher_config["language"] == "s3boot"
    assert rule.condition is not None
    assert "trusted_execution" in rule.condition


@pytest.mark.parametrize(
    "invalid_yaml",
    [
        VALID_RULE.replace("severity: critical", "severity: emergency"),
        VALID_RULE.replace("plugin: s3bootscript", "plugin: ../../untrusted.py"),
        VALID_RULE.replace("schema_version: 1", "schema_version: 99"),
        VALID_RULE.replace("required_fields:", "required_range_sets:"),
        VALID_RULE.replace("    - trusted_execution", "    - 42"),
        VALID_RULE.replace("    - trusted_execution", "    - ''"),
        VALID_RULE + "unknown_section: true\n",
        "!!python/object/apply:os.system ['echo unsafe']\n",
    ],
)
def test_loader_rejects_invalid_or_executable_rule_data(invalid_yaml: str) -> None:
    result = YamlRuleLoader().load(
        [_source("invalid.rule.yaml", invalid_yaml)],
        AcceptingPlugin(),
    )

    assert not result.rules
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].source == "invalid.rule.yaml"


def test_loader_keeps_valid_rules_when_another_source_is_malformed() -> None:
    sources = [
        _source("broken.rule.yaml", "metadata: [unterminated"),
        _source("dispatch.rule.yaml", VALID_RULE),
    ]

    result = YamlRuleLoader().load(sources, AcceptingPlugin())

    assert [rule.rule_id for rule in result.rules] == ["S3-DISPATCH-001"]
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].source == "broken.rule.yaml"


def test_loader_preserves_source_order() -> None:
    second_rule = VALID_RULE.replace("S3-DISPATCH-001", "S3-DISPATCH-002")

    result = YamlRuleLoader().load(
        [_source("first.rule.yaml", VALID_RULE), _source("second.rule.yaml", second_rule)],
        AcceptingPlugin(),
    )

    assert [rule.rule_id for rule in result.rules] == [
        "S3-DISPATCH-001",
        "S3-DISPATCH-002",
    ]


def test_loader_rejects_duplicate_rule_ids_without_losing_first_rule() -> None:
    result = YamlRuleLoader().load(
        [_source("first.rule.yaml", VALID_RULE), _source("duplicate.rule.yaml", VALID_RULE)],
        AcceptingPlugin(),
    )

    assert [rule.rule_id for rule in result.rules] == ["S3-DISPATCH-001"]
    assert result.diagnostics[0].code == "duplicate_rule_id"


def test_loader_rejects_a_rule_for_another_selected_plugin() -> None:
    incompatible = VALID_RULE.replace("plugin: s3bootscript", "plugin: acpi")

    result = YamlRuleLoader().load(
        [_source("acpi.rule.yaml", incompatible)],
        AcceptingPlugin(),
    )

    assert not result.rules
    assert result.diagnostics[0].code == "invalid_rule"
    assert "does not match selected plugin" in result.diagnostics[0].message


def test_loader_accepts_arbitrary_required_field_names() -> None:
    text = VALID_RULE.replace("trusted_execution", "allowed_identifiers")

    result = YamlRuleLoader().load([_source("generic.yaml", text)], AcceptingPlugin())

    assert not result.diagnostics
    assert result.rules[0].required_fields == ("allowed_identifiers",)


def _source(name: str, text: str) -> RuleSource:
    return RuleSource(name=name, text=text)
