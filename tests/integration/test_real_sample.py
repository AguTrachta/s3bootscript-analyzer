import json
import logging
from pathlib import Path
from typing import Any

import pytest
from pytest import CaptureFixture, LogCaptureFixture

from s3bootscript_analyzer.cli import EXIT_SUCCESS, main
from s3bootscript_analyzer.errors import RawParseError
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.parsers import KaitaiBootScriptRawParser

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_BINARY = PROJECT_ROOT / "samples" / "binaries" / "s3bootscript.bin"
EXPECTED_SEMANTIC = PROJECT_ROOT / "tests" / "fixtures" / "expected" / "s3bootscript.semantic.txt"
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"
SAMPLE_SIZE = 1483


def test_sample_binary_exists_as_real_lfs_content() -> None:
    assert SAMPLE_BINARY.exists()
    data = SAMPLE_BINARY.read_bytes()

    assert len(data) == SAMPLE_SIZE
    assert not data.startswith(LFS_POINTER_PREFIX)


def test_kaitai_parser_reads_real_sample_metadata() -> None:
    raw_script = _parse_sample()

    assert int(raw_script.table_header.magic) == 0xAA
    assert raw_script.table_header.length == 13
    assert raw_script.table_header.version == 1
    assert raw_script.table_header.table_length == SAMPLE_SIZE
    assert len(raw_script.records) == 63
    assert raw_script.records[0].offset == 0x0D
    assert raw_script.records[-1].offset == 0x5C8
    assert raw_script.records[-1].opcode_id == 0xFF


def test_kaitai_parser_wraps_malformed_input() -> None:
    source = BinarySource(path=Path("malformed.bin"), data=b"\xaa")

    with pytest.raises(RawParseError):
        KaitaiBootScriptRawParser().parse(source)


def test_kaitai_parser_debug_logs_malformed_input_context(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="s3bootscript_analyzer.parsers.kaitai")
    source = BinarySource(
        path=Path("malformed.bin"),
        data=bytes.fromhex("aa000d0100140000000000000002"),
    )

    with pytest.raises(RawParseError):
        KaitaiBootScriptRawParser().parse(source)

    messages = [record.message for record in caplog.records]
    assert any(
        "starting Kaitai parse path=malformed.bin size=14" in message for message in messages
    )
    assert any(
        "header preview opcode=0xaa length=13 version=0x1 table_length=20 input_size=14" in message
        for message in messages
    )
    assert any("Kaitai parse failed cause_type=EndOfStreamError" in message for message in messages)


def test_cli_text_output_for_real_sample(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["--input-binary", str(SAMPLE_BINARY), "--output-format", "text"])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert "BOOT_SCRIPT_TABLE magic=0xaa length=13 version=0x1 table_length=1483" in captured.out
    assert "0x24: MEM_WRITE" in captured.out
    assert "0x39: MEM_POLL" in captured.out
    assert "0x2de: PCI_CONFIG_WRITE" in captured.out
    assert captured.out.rstrip().endswith("0x5c8: TERMINATE")


def test_cli_json_output_for_real_sample(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["--input-binary", str(SAMPLE_BINARY), "--output-format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == EXIT_SUCCESS
    assert data["header"] == {
        "magic": "0xaa",
        "length": 13,
        "version": "0x1",
        "table_length": SAMPLE_SIZE,
    }
    assert len(data["records"]) == 63
    assert data["records"][0]["offset"] == "0xd"
    assert data["records"][0]["mnemonic"] == "IO_READ_WRITE"
    assert _record_mnemonics(data) >= {"MEM_WRITE", "MEM_POLL", "PCI_CONFIG_WRITE", "TERMINATE"}
    assert data["records"][-1]["offset"] == "0x5c8"
    assert data["records"][-1]["mnemonic"] == "TERMINATE"


def test_cli_semantic_output_matches_stable_golden(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["--input-binary", str(SAMPLE_BINARY), "--output-format", "semantic"])
    captured = capsys.readouterr()

    assert exit_code == EXIT_SUCCESS
    assert captured.out == EXPECTED_SEMANTIC.read_text(encoding="utf-8")
    assert "mem[0xd0b30000] <- 0x0001" in captured.out
    assert "poll until (mem[0xd0b30000] & 0x0001) == 0x0001" in captured.out
    assert "pci[0x200fc] <- 0x77263018" in captured.out
    assert "TERMINATE" not in captured.out


def _parse_sample() -> Any:
    return KaitaiBootScriptRawParser().parse(
        BinarySource(path=SAMPLE_BINARY, data=SAMPLE_BINARY.read_bytes())
    )


def _record_mnemonics(data: dict[str, Any]) -> set[str]:
    return {str(record["mnemonic"]) for record in data["records"]}
