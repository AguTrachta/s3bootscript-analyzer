"""Outside-in condition stories; the simpleeval adapter is the next production step."""

import json
import shutil
import struct
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from s3bootscript_analyzer import analysis
from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisProfile,
    AnalysisRequest,
    AnalyzeArtifact,
    ConditionEvaluator,
    EvaluationOutcome,
    ProfileSelection,
    RuleExecutionError,
    Severity,
)
from s3bootscript_analyzer.extensions import PluginCatalog
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.ir import SemanticIrBuilder
from s3bootscript_analyzer.matchers import AstGrepMatcher
from s3bootscript_analyzer.parsers.kaitai import KaitaiBootScriptRawParser
from s3bootscript_analyzer.plugins import S3BootScriptPlugin
from s3bootscript_analyzer.profile_data import JsonProfileLoader
from s3bootscript_analyzer.rules import RuleSource, YamlRuleLoader

PROJECT_ROOT = Path(__file__).resolve().parents[2]
KERNEL_CONDITION = (
    'any([r["name"] == "KERNEL_CODE_RANGE" and r["start"] <= ADDR <= r["end"] '
    'for r in profile["ranges"]])'
)


def test_only_writes_inside_reported_kernel_code_reach_the_report(tmp_path: Path) -> None:
    # Arrange
    use_case = _analysis()
    request = _request(
        tmp_path,
        (_memory_write_rule("S3-KERNEL-WRITE", KERNEL_CONDITION),),
        {"ranges": [{"name": "KERNEL_CODE_RANGE", "start": 0x1000, "end": 0x1FFF}]},
    )

    # Act
    report = use_case.execute(request)

    # Assert
    assert len(report.evaluations) == 1
    assert report.evaluations[0].outcome is EvaluationOutcome.MATCHED
    assert report.evaluations[0].rule.severity is Severity.WARNING
    evidence = report.evaluations[0].evidence
    assert len(evidence) == 1
    assert evidence[0].bindings == {"ADDR": 0x1800, "VALUE": 1}
    assert evidence[0].semantic_text == "mem[0x1800] <- 0x01"
    assert evidence[0].record_index == 0
    assert evidence[0].opcode_offset == 0x0D
    assert evidence[0].record["fields"] == {
        "width": 0,
        "count": 1,
        "address": 0x1800,
        "buffer": (1,),
    }


def test_writes_outside_reported_kernel_code_produce_no_finding(tmp_path: Path) -> None:
    # Arrange
    use_case = _analysis()
    request = _request(
        tmp_path,
        (_memory_write_rule("S3-KERNEL-WRITE", KERNEL_CONDITION),),
        {"ranges": [{"name": "KERNEL_CODE_RANGE", "start": 0x4000, "end": 0x4FFF}]},
    )

    # Act
    report = use_case.execute(request)

    # Assert
    assert report.evaluations[0].outcome is EvaluationOutcome.NOT_MATCHED
    assert report.evaluations[0].evidence == ()
    assert report.evaluations[0].diagnostics == ()


@pytest.mark.parametrize(
    ("limit", "expected"),
    [(1, EvaluationOutcome.MATCHED), (0, EvaluationOutcome.NOT_MATCHED)],
)
def test_rule_can_filter_on_raw_count_not_present_in_semantic_text(
    tmp_path: Path, limit: int, expected: EvaluationOutcome
) -> None:
    use_case = _analysis()
    request = _request(
        tmp_path,
        (_memory_write_rule("S3-COUNT", 'record["fields"]["count"] <= profile["limit"]'),),
        {"limit": limit},
    )

    report = use_case.execute(request)

    assert report.evaluations[0].outcome is expected


def test_failed_condition_is_reported_and_a_later_rule_still_finds_a_write(tmp_path: Path) -> None:
    # Arrange
    use_case = _analysis()
    request = _request(
        tmp_path,
        (
            _memory_write_rule("S3-BROKEN", 'ADDR >= profile["limits"]["minimum"]'),
            _memory_write_rule("S3-KERNEL-WRITE", KERNEL_CONDITION),
        ),
        {
            "limits": {},
            "ranges": [{"name": "KERNEL_CODE_RANGE", "start": 0x1000, "end": 0x1FFF}],
        },
    )

    # Act
    report = use_case.execute(request)

    # Assert
    assert tuple((item.rule.rule_id, item.outcome) for item in report.evaluations) == (
        ("S3-BROKEN", EvaluationOutcome.ERROR),
        ("S3-KERNEL-WRITE", EvaluationOutcome.MATCHED),
    )
    assert report.evaluations[0].evidence == ()
    assert report.evaluations[0].diagnostics[0].code == "rule_execution_error"
    assert report.evaluations[0].diagnostics[0].source == "S3-BROKEN"
    assert "minimum" in report.evaluations[0].diagnostics[0].message
    assert tuple(item.bindings["ADDR"] for item in report.evaluations[1].evidence) == (0x1800,)


def test_missing_record_field_reports_error_and_later_rule_continues(tmp_path: Path) -> None:
    request = _request(
        tmp_path,
        (
            _memory_write_rule("S3-MISSING", 'record["fields"]["missing"] == 1'),
            _memory_write_rule("S3-COUNT", 'record["fields"]["count"] == 1'),
        ),
        {},
    )

    report = _analysis().execute(request)

    assert [item.outcome for item in report.evaluations] == [
        EvaluationOutcome.ERROR,
        EvaluationOutcome.MATCHED,
    ]
    assert "missing" in report.evaluations[0].diagnostics[0].message


def test_count_within_a_producers_nested_limit_is_accepted() -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('COUNT <= profile["limits"]["maximum_count"]')
    profile = AnalysisProfile(name="producer", data={"limits": {"maximum_count": 128}})

    # Act
    accepted = evaluator.evaluate(condition, {"COUNT": 64}, profile.data, {})

    # Assert
    assert accepted is True


def test_identifier_outside_a_producers_allowed_list_is_rejected() -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('IDENTIFIER in profile["allowed_identifiers"]')
    profile = AnalysisProfile(name="producer", data={"allowed_identifiers": ["alpha", "beta"]})

    # Act
    accepted = evaluator.evaluate(condition, {"IDENTIFIER": "gamma"}, profile.data, {})

    # Assert
    assert accepted is False


def test_a_producers_auditing_flag_can_decide_a_condition() -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('profile["features"]["auditing_required"]')
    profile = AnalysisProfile(name="producer", data={"features": {"auditing_required": True}})

    # Act
    accepted = evaluator.evaluate(condition, {}, profile.data, {})

    # Assert
    assert accepted is True


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param("ADDR >=", id="incomplete-comparison"),
        pytest.param("True; False", id="multiple-statements"),
    ],
)
def test_unusable_condition_is_a_compilation_error(expression: str) -> None:
    # Arrange
    evaluator = _evaluator()

    # Act / Assert
    with pytest.raises(RuleExecutionError):
        evaluator.compile(expression)


@pytest.mark.parametrize(
    ("expression", "facts"),
    [
        pytest.param(
            'COUNT <= profile["limits"]["maximum_count"]',
            {"limits": {}},
            id="missing-nested-fact",
        ),
        pytest.param(
            'COUNT <= profile["limits"]["maximum_count"]',
            {"limits": {"maximum_count": "unknown"}},
            id="incompatible-fact-type",
        ),
        pytest.param("COUNT", {}, id="truthy-number-is-not-a-boolean-decision"),
        pytest.param("rand() >= 0", {}, id="unselected-function"),
    ],
)
def test_failed_condition_never_becomes_an_accepted_or_rejected_candidate(
    expression: str, facts: Mapping[str, object]
) -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile(expression)
    profile = AnalysisProfile(name="producer", data=facts)

    # Act / Assert
    with pytest.raises(RuleExecutionError):
        evaluator.evaluate(condition, {"COUNT": 1}, profile.data, {})


@pytest.mark.parametrize(
    ("address", "profile", "expected"),
    [
        pytest.param(
            2**53 + 1,
            AnalysisProfile(name="producer", data={"address": 2**53}),
            False,
            id="adjacent-above-float-precision",
        ),
        pytest.param(
            2**64 - 1,
            AnalysisProfile(name="producer", data={"address": 2**64 - 1}),
            True,
            id="maximum-unsigned-address",
        ),
        pytest.param(
            2**64 - 1,
            AnalysisProfile(name="producer", data={"address": 2**64 - 2}),
            False,
            id="adjacent-unsigned-addresses",
        ),
    ],
)
def test_address_comparisons_preserve_exact_integer_values(
    address: int, profile: AnalysisProfile, expected: bool
) -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('ADDR == profile["address"]')

    # Act
    accepted = evaluator.evaluate(condition, {"ADDR": address}, profile.data, {})

    # Assert
    assert accepted is expected


def test_later_candidate_cannot_inherit_an_earlier_candidates_capture() -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('ENTRY == profile["allowed_entry"]')
    profile = AnalysisProfile(name="producer", data={"allowed_entry": 0x1000})
    evaluator.evaluate(condition, {"ENTRY": 0x1000}, profile.data, {})

    # Act / Assert
    with pytest.raises(RuleExecutionError, match="ENTRY"):
        evaluator.evaluate(condition, {}, profile.data, {})


def test_capture_cannot_replace_the_reserved_profile() -> None:
    # Arrange
    evaluator = _evaluator()
    condition = evaluator.compile('profile["enabled"]')
    profile = AnalysisProfile(name="producer", data={"enabled": True})

    # Act / Assert
    with pytest.raises(RuleExecutionError, match="profile"):
        evaluator.evaluate(condition, {"profile": True}, profile.data, {})


def test_condition_can_read_raw_record_fields_without_changing_captures() -> None:
    evaluator = _evaluator()
    condition = evaluator.compile('record["fields"]["count"] <= profile["limit"]')
    profile = AnalysisProfile(name="producer", data={"limit": 2})

    accepted = evaluator.evaluate(
        condition, {"ADDR": 0x1800}, profile.data, {"fields": {"count": 1}}
    )

    assert accepted is True


def test_record_capture_is_rejected_by_direct_condition_evaluation() -> None:
    evaluator = _evaluator()
    condition = evaluator.compile('record["fields"]["count"] == 1')

    with pytest.raises(RuleExecutionError, match="record"):
        evaluator.evaluate(condition, {"record": 1}, {}, {"fields": {"count": 1}})


def _evaluator() -> ConditionEvaluator:
    factory = vars(analysis).get("SimpleEvalConditionEvaluator")
    assert callable(factory), "SimpleEvalConditionEvaluator is not implemented/exported yet"
    constructor = cast(Callable[[], ConditionEvaluator], factory)
    return constructor()


def _analysis() -> AnalyzeArtifact:
    evaluator = _evaluator()
    matcher = AstGrepMatcher(
        executable=Path(shutil.which("ast-grep") or Path(sys.executable).with_name("ast-grep")),
        config_path=PROJECT_ROOT / "tools" / "semantic_ir" / "sgconfig.yml",
    )
    plugin = S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder(), [matcher])
    return AnalyzeArtifact(
        plugins=PluginCatalog([plugin]),
        rules=YamlRuleLoader(),
        profiles=JsonProfileLoader(),
        engine=AnalysisEngine(evaluator),
    )


def _request(
    tmp_path: Path, rule_sources: tuple[RuleSource, ...], facts: Mapping[str, object]
) -> AnalysisRequest:
    profile_path = tmp_path / "producer.json"
    profile_path.write_text(json.dumps(facts), encoding="utf-8")
    return AnalysisRequest(
        artifact=_two_write_script(),
        plugin_id="s3bootscript",
        rule_sources=rule_sources,
        profile_selection=ProfileSelection(profile_path),
    )


def _memory_write_rule(rule_id: str, expression: str) -> RuleSource:
    return RuleSource(
        f"{rule_id}.yaml",
        f"""\
schema_version: 1
plugin: s3bootscript
metadata:
  id: {rule_id}
  title: Memory write selected by profile facts
  severity: warning
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: mem[$ADDR] <- $VALUE
condition:
  language: simpleeval
  expression: >-
    {expression}
""",
    )


def _two_write_script() -> BinarySource:
    # UInt8 MEM_WRITE records: opcode, length, width, count, address, value.
    records = (
        struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x1800, 1)
        + struct.pack("<HBIIQB", 0x02, 20, 0, 1, 0x3000, 2)
        + struct.pack("<HB", 0xFF, 3)
    )
    # Table header: opcode, length, version, total length, two reserved fields.
    header = struct.pack("<HBHIHH", 0xAA, 13, 1, 13 + len(records), 0, 0)
    return BinarySource(path=Path("two-writes.bin"), data=header + records)
