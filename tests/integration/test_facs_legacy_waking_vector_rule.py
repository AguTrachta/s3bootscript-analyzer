"""The FACS rule identifies whole writes starting at the legacy vector."""

import json
import shutil
import struct
import sys
from pathlib import Path

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisRequest,
    AnalyzeArtifact,
    EvaluationOutcome,
    ProfileSelection,
    RuleEvaluation,
    Severity,
    SimpleEvalConditionEvaluator,
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
RULE_PATH = PROJECT_ROOT / "rules/base/facs-legacy-waking-vector-write.rule.yaml"
FACS_BASE = 0x3B7CA000
LEGACY_VECTOR = FACS_BASE + 0x0C


@pytest.mark.parametrize(
    ("address", "width", "count", "expected"),
    [
        (LEGACY_VECTOR, 2, 1, EvaluationOutcome.MATCHED),
        (LEGACY_VECTOR + 1, 2, 1, EvaluationOutcome.NOT_MATCHED),
        (LEGACY_VECTOR, 0, 1, EvaluationOutcome.NOT_MATCHED),
        (LEGACY_VECTOR, 2, 2, EvaluationOutcome.MATCHED),
        (LEGACY_VECTOR, 2, 0, EvaluationOutcome.NOT_MATCHED),
    ],
)
def test_rule_selects_uint32_writes_starting_at_legacy_vector(
    tmp_path: Path, address: int, width: int, count: int, expected: EvaluationOutcome
) -> None:
    evaluation = _analyze(_mem_write(address, width, count), _profile(tmp_path))

    assert evaluation.outcome is expected
    assert evaluation.rule.severity is Severity.CRITICAL


def test_rule_does_not_classify_mem_read_write_as_direct_vector_replacement(
    tmp_path: Path,
) -> None:
    evaluation = _analyze(_mem_read_write(LEGACY_VECTOR), _profile(tmp_path))

    assert evaluation.outcome is EvaluationOutcome.NOT_MATCHED


def test_rule_reports_unknown_when_facs_profile_is_missing(tmp_path: Path) -> None:
    profile_path = tmp_path / "empty.json"
    profile_path.write_text("{}", encoding="utf-8")

    evaluation = _analyze(_mem_write(LEGACY_VECTOR, 2, 1), profile_path)

    assert evaluation.outcome is EvaluationOutcome.UNKNOWN


def _profile(directory: Path) -> Path:
    profile_path = directory / "facs.json"
    profile_path.write_text(
        json.dumps({"facs": {"legacy_waking_vector": {"start": LEGACY_VECTOR}}}),
        encoding="utf-8",
    )
    return profile_path


def _mem_write(address: int, width: int, count: int) -> BinarySource:
    payload = bytes(count * (1 << width))
    body = struct.pack("<IIQ", width, count, address) + payload
    return _script(struct.pack("<HB", 0x02, 3 + len(body)) + body)


def _mem_read_write(address: int) -> BinarySource:
    body = struct.pack("<IQII", 2, address, 1, 0xFFFFFFFF)
    return _script(struct.pack("<HB", 0x03, 3 + len(body)) + body)


def _script(record: bytes) -> BinarySource:
    records = record + struct.pack("<HB", 0xFF, 3)
    header = struct.pack("<HBHIHH", 0xAA, 13, 1, 13 + len(records), 0, 0)
    return BinarySource(path=Path("facs-write.bin"), data=header + records)


def _analyze(binary: BinarySource, profile_path: Path) -> RuleEvaluation:
    matcher = AstGrepMatcher(
        executable=Path(shutil.which("ast-grep") or Path(sys.executable).with_name("ast-grep")),
        config_path=PROJECT_ROOT / "tools/semantic_ir/sgconfig.yml",
    )
    plugin = S3BootScriptPlugin(KaitaiBootScriptRawParser(), SemanticIrBuilder(), [matcher])
    analyzer = AnalyzeArtifact(
        plugins=PluginCatalog([plugin]),
        rules=YamlRuleLoader(),
        profiles=JsonProfileLoader(),
        engine=AnalysisEngine(SimpleEvalConditionEvaluator()),
    )
    request = AnalysisRequest(
        artifact=binary,
        plugin_id="s3bootscript",
        rule_sources=(RuleSource(str(RULE_PATH), RULE_PATH.read_text(encoding="utf-8")),),
        profile_selection=ProfileSelection(profile_path),
    )
    return analyzer.execute(request).evaluations[0]
