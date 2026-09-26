"""Outside-in stories for the concrete S3 ast-grep matcher.

Real matching uses the installed backend and S3 grammar.
Only operational failures replace the external process boundary.
"""

import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisProfile,
    EvaluationOutcome,
    MatchEvidence,
    RuleDefinition,
    RuleExecutionError,
)
from s3bootscript_analyzer.analysis.contracts import ConditionEvaluator
from s3bootscript_analyzer.ir.semantic import (
    SemanticIrBuilder,
    SemanticIrDocument,
    SemanticRecord,
    SemanticSourceReference,
)
from s3bootscript_analyzer.matchers import AstGrepMatcher
from s3bootscript_analyzer.parsers.kaitai import KaitaiBootScriptRawParser
from s3bootscript_analyzer.plugins import S3BootScriptPlugin
from s3bootscript_analyzer.rules import RuleSource, YamlRuleLoader

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AST_GREP_CONFIG = PROJECT_ROOT / "tools" / "semantic_ir" / "sgconfig.yml"
AST_GREP_EXECUTABLE = Path(shutil.which("ast-grep") or Path(sys.executable).with_name("ast-grep"))
MEMORY_WRITE_RULE = """\
schema_version: 1
plugin: s3bootscript
metadata:
  id: S3-MEM-WRITE
  title: Locate memory writes
  severity: informational
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: mem[$ADDR] <- $VALUE
"""


def test_memory_writes_retain_numeric_captures_and_binary_origins_in_source_order() -> None:
    # Arrange
    plugin = _plugin()
    rule = _load_memory_write_rule(plugin)
    document = _mixed_script()

    # Act
    evidence = tuple(plugin.match(document, rule))

    # Assert
    assert evidence == (
        MatchEvidence(
            bindings={"ADDR": 0x9000, "VALUE": 1},
            semantic_text="mem[0x9000] <- 0x01",
            semantic_line=1,
            record_index=2,
            opcode_offset=0x30,
            record=document.records[2].context,
        ),
        MatchEvidence(
            bindings={"ADDR": 0x1000, "VALUE": 42},
            semantic_text="mem[0x1000] <- 0x2a",
            semantic_line=3,
            record_index=7,
            opcode_offset=0x90,
            record=document.records[7].context,
        ),
    )


def test_dispatch_only_script_has_no_memory_write_evidence() -> None:
    # Arrange
    plugin = _plugin()
    rule = _load_memory_write_rule(plugin)
    document = SemanticIrDocument(
        text="call 0x8000\n",
        source_map=(SemanticSourceReference(1, 0, 0x0D),),
    )

    # Act
    evidence = tuple(plugin.match(document, rule))

    # Assert
    assert not evidence


def test_literal_memory_write_rule_delivers_evidence_without_captures() -> None:
    # Arrange
    plugin = _plugin()
    source = RuleSource(
        "literal-write.yaml",
        MEMORY_WRITE_RULE.replace("mem[$ADDR] <- $VALUE", "mem[0x9000] <- 0x01"),
    )
    rule = YamlRuleLoader().load((source,), plugin).rules[0]
    document = _mixed_script()

    # Act
    evidence = tuple(plugin.match(document, rule))

    # Assert
    assert evidence == (
        MatchEvidence(
            bindings={},
            semantic_text="mem[0x9000] <- 0x01",
            semantic_line=1,
            record_index=2,
            opcode_offset=0x30,
            record=document.records[2].context,
        ),
    )


def test_rules_load_native_configuration_without_a_registered_matcher() -> None:
    # Arrange
    plugin = S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder())
    source = RuleSource(
        "native-rule.yaml",
        MEMORY_WRITE_RULE.replace("language: s3boot", "language: JavaScript").replace(
            "pattern: mem[$ADDR] <- $VALUE",
            "pattern: $CALL($ARG)\n    utils:\n      module:\n        kind: identifier",
        ),
    )

    # Act
    result = YamlRuleLoader().load((source,), plugin)

    # Assert
    assert not result.diagnostics
    assert result.rules[0].matcher_config == {
        "language": "JavaScript",
        "rule": {"pattern": "$CALL($ARG)"},
        "utils": {"module": {"kind": "identifier"}},
    }


def test_missing_backend_configuration_is_reported_only_when_matching(tmp_path: Path) -> None:
    # Arrange
    matcher = AstGrepMatcher(AST_GREP_EXECUTABLE, tmp_path / "missing.yml")
    plugin = S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder(), [matcher])
    source = RuleSource("memory-write.yaml", MEMORY_WRITE_RULE)
    rule = YamlRuleLoader().load((source,), plugin).rules[0]
    document = _mixed_script()

    # Act / Assert
    with pytest.raises(RuleExecutionError, match="configuration"):
        tuple(plugin.match(document, rule))


@pytest.mark.parametrize(
    ("process_result", "error_detail"),
    [
        pytest.param(
            FileNotFoundError("ast-grep executable is unavailable"),
            r"(?i)(executable|unavailable|not found)",
            id="executable-unavailable",
        ),
        pytest.param(
            subprocess.CompletedProcess(
                args=["ast-grep"], returncode=2, stdout="", stderr="backend read failed"
            ),
            "backend read failed",
            id="failed-exit-retains-stderr",
        ),
        pytest.param(
            subprocess.TimeoutExpired(cmd="ast-grep", timeout=10.0),
            r"(?i)(timeout|timed out)",
            id="backend-timeout",
        ),
        pytest.param(
            subprocess.CompletedProcess(
                args=["ast-grep"], returncode=0, stdout="not JSON\n", stderr=""
            ),
            r"(?i)(json|output)",
            id="malformed-backend-output",
        ),
    ],
)
def test_untrustworthy_backend_result_is_an_execution_error_not_an_empty_match(
    process_result: Exception | subprocess.CompletedProcess[str],
    error_detail: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange
    plugin = _plugin()
    rule = _load_memory_write_rule(plugin)
    document = _mixed_script()
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=(process_result,)))

    # Act / Assert
    with pytest.raises(RuleExecutionError, match=error_detail):
        tuple(plugin.match(document, rule))


def test_invalid_native_rule_is_reported_and_a_later_rule_still_delivers_evidence() -> None:
    # Arrange
    plugin = _plugin()
    sources = (
        RuleSource(
            "invalid.yaml",
            MEMORY_WRITE_RULE.replace("S3-MEM-WRITE", "S3-FIRST").replace(
                "pattern: mem[$ADDR] <- $VALUE", "kind: nonexistent_s3_opcode"
            ),
        ),
        RuleSource("later.yaml", MEMORY_WRITE_RULE.replace("S3-MEM-WRITE", "S3-LATER")),
    )
    rules = YamlRuleLoader().load(sources, plugin).rules
    document = SemanticIrDocument(
        text="mem[0x9000] <- 0x01\n",
        source_map=(SemanticSourceReference(1, 2, 0x30),),
        records=_mixed_script().records,
    )
    engine = AnalysisEngine(condition_evaluator=Mock(spec=ConditionEvaluator))

    # Act
    evaluations = engine.evaluate(document, rules, AnalysisProfile(name="empty", data={}), plugin)

    # Assert
    assert tuple((item.rule.rule_id, item.outcome) for item in evaluations) == (
        ("S3-FIRST", EvaluationOutcome.ERROR),
        ("S3-LATER", EvaluationOutcome.MATCHED),
    )
    assert evaluations[0].evidence == ()
    assert evaluations[0].diagnostics[0].code == "rule_execution_error"
    assert "nonexistent_s3_opcode" in evaluations[0].diagnostics[0].message
    assert evaluations[1].evidence == (
        MatchEvidence(
            bindings={"ADDR": 0x9000, "VALUE": 1},
            semantic_text="mem[0x9000] <- 0x01",
            semantic_line=1,
            record_index=2,
            opcode_offset=0x30,
            record=document.records[2].context,
        ),
    )


def _plugin() -> S3BootScriptPlugin:
    matcher = AstGrepMatcher(
        executable=AST_GREP_EXECUTABLE,
        config_path=AST_GREP_CONFIG,
        timeout_seconds=10.0,
    )
    return S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder(), [matcher])


def _load_memory_write_rule(
    plugin: S3BootScriptPlugin,
    rule_id: str = "S3-MEM-WRITE",
) -> RuleDefinition:
    source = RuleSource("memory-write.yaml", MEMORY_WRITE_RULE.replace("S3-MEM-WRITE", rule_id))
    return YamlRuleLoader().load((source,), plugin).rules[0]


def _mixed_script() -> SemanticIrDocument:
    return SemanticIrDocument(
        text="mem[0x9000] <- 0x01\ncall 0x8000\nmem[0x1000] <- 0x2a\n",
        source_map=(
            SemanticSourceReference(1, 2, 0x30),
            SemanticSourceReference(2, 4, 0x60),
            SemanticSourceReference(3, 7, 0x90),
        ),
        records=tuple(
            SemanticRecord(
                record_index=index,
                offset={2: 0x30, 4: 0x60, 7: 0x90}.get(index, 0),
                opcode_id=2,
                opcode="MEM_WRITE",
                length=3,
                raw_bytes=b"\x02\x00\x03",
                fields={},
            )
            for index in range(8)
        ),
    )
