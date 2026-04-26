import json
from types import SimpleNamespace

from s3bootscript_analyzer.engine.opcodes import OpcodeId
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawOpcodeRecord, RawTableHeader
from s3bootscript_analyzer.reporting import JsonIrRenderer, SemanticIrRenderer, TextIrRenderer


def test_text_renderer_includes_header_records_and_semantic_annotations() -> None:
    raw_script = _sample_raw_script()
    opcode_lines = ["0xd: MEM_WRITE width=uint16 count=0x1 address=0x1000 buffer=01,00"]

    rendered = TextIrRenderer().render(raw_script, "BOOT_SCRIPT_TABLE magic=0xaa", opcode_lines)

    assert rendered.startswith("BOOT_SCRIPT_TABLE magic=0xaa\n")
    assert "0xd: MEM_WRITE" in rendered
    assert "| mem[address] <- buffer" in rendered


def test_json_renderer_outputs_structural_fields() -> None:
    rendered = JsonIrRenderer().render(_sample_raw_script(), "", [])
    data = json.loads(rendered)

    assert data["header"] == {
        "magic": "0xaa",
        "length": 13,
        "version": "0x1",
        "table_length": 34,
    }
    assert data["records"][0]["offset"] == "0xd"
    assert data["records"][0]["mnemonic"] == "MEM_WRITE"
    assert data["records"][0]["fields"]["buffer"] == "01,00"


def test_semantic_renderer_outputs_resolved_expressions() -> None:
    rendered = SemanticIrRenderer().render(_sample_raw_script(), "", [])

    assert rendered == "mem[0x1000] <- 0x0001\n"


def _sample_raw_script() -> RawBootScript:
    return RawBootScript(
        table_header=RawTableHeader(magic=0xAA, length=13, version=1, table_length=34),
        records=[
            RawOpcodeRecord(
                opcode_id=int(OpcodeId.MEM_WRITE),
                length=21,
                offset=0x0D,
                body=SimpleNamespace(width="uint16", count=1, address=0x1000, buffer=b"\x01\x00"),
                raw_bytes=b"\x02\x00\x15" + b"\x00" * 18,
            )
        ],
    )
