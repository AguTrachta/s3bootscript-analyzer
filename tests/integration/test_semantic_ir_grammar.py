"""Integration contract between the existing semantic IR, Tree-sitter, and ast-grep."""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEMANTIC_GOLDEN = PROJECT_ROOT / "tests" / "fixtures" / "expected" / "s3bootscript.semantic.txt"
AST_GREP_CONFIG = PROJECT_ROOT / "tools" / "semantic_ir" / "sgconfig.yml"
AST_GREP_PATH = shutil.which("ast-grep") or str(Path(sys.executable).with_name("ast-grep"))

if not Path(AST_GREP_PATH).is_file():
    pytest.skip(
        "ast-grep is not on PATH; install ast-grep-cli to run semantic grammar contracts",
        allow_module_level=True,
    )

AST_GREP_EXECUTABLE = AST_GREP_PATH


@pytest.mark.parametrize(
    ("pattern", "capture", "expected"),
    [
        ("mem[$ADDR] <- $VALUE", "ADDR", "0xd0b30000"),
        ("poll until (mem[$ADDR] & $MASK) == $VALUE", "MASK", "0x0001"),
        ("pci[$ADDR] <- $VALUE", "ADDR", "0x200fc"),
    ],
)
def test_ast_grep_matches_the_existing_semantic_ir_golden(
    pattern: str,
    capture: str,
    expected: str,
    tmp_path: Path,
) -> None:
    rule_path = tmp_path / "contract-rule.yaml"
    rule_path.write_text(_rule_yaml(pattern), encoding="utf-8")

    matches = _scan(rule_path)

    assert matches
    assert matches[0]["metaVariables"]["single"][capture]["text"] == expected


def _scan(rule_path: Path) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            AST_GREP_EXECUTABLE,
            "scan",
            "--rule",
            str(rule_path),
            "--config",
            str(AST_GREP_CONFIG),
            "--json=stream",
            str(SEMANTIC_GOLDEN),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    return [json.loads(line) for line in completed.stdout.splitlines() if line]


def _rule_yaml(pattern: str) -> str:
    return "\n".join(
        [
            "id: semantic-ir-contract",
            "language: s3boot",
            "rule:",
            f"  pattern: {pattern}",
            "",
        ]
    )
