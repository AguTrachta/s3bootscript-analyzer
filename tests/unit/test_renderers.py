import json
from types import SimpleNamespace

import pytest

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


@pytest.mark.parametrize(
    ("opcode_id", "body", "expected"),
    [
        (
            OpcodeId.MEM_READ_WRITE,
            SimpleNamespace(
                width="uint16",
                address=0x1000,
                data=b"\x01\x00",
                data_mask=b"\xff\x00",
            ),
            "mem[0x1000] <- (mem[0x1000] & 0x00ff) | 0x0001\n",
        ),
        (
            OpcodeId.MEM_POLL,
            SimpleNamespace(
                width="uint16",
                address=0x2000,
                duration=1,
                loop_times=2,
                data=b"\x04\x00",
                data_mask=b"\xff\x00",
            ),
            "poll until (mem[0x2000] & 0x00ff) == 0x0004\n",
        ),
        (
            OpcodeId.PCI_CONFIG2_WRITE,
            SimpleNamespace(
                width="uint32",
                count=1,
                address=0x100,
                segment=2,
                buffer=b"\x78\x56\x34\x12",
            ),
            "pci[0x2:0x100] <- 0x12345678\n",
        ),
        (
            OpcodeId.DISPATCH,
            SimpleNamespace(entry_point=0x8000),
            "call 0x8000\n",
        ),
        (
            OpcodeId.DISPATCH_2,
            SimpleNamespace(entry_point=0x8000, context=0x9000),
            "call 0x8000(0x9000)\n",
        ),
    ],
)
def test_semantic_renderer_preserves_existing_s3boot_syntax(
    opcode_id: OpcodeId,
    body: SimpleNamespace,
    expected: str,
) -> None:
    raw_script = _raw_script([_record(opcode_id, body, offset=0x0D)])

    assert SemanticIrRenderer().render(raw_script, "", []) == expected


def test_semantic_renderer_omits_nonsemantic_opcodes_without_reordering() -> None:
    records = [
        _record(
            OpcodeId.MEM_WRITE,
            SimpleNamespace(width="uint16", count=1, address=0x1000, buffer=b"\x01\x00"),
            offset=0x0D,
        ),
        _record(OpcodeId.TERMINATE, object(), offset=0x22),
        _record(
            OpcodeId.MEM_WRITE,
            SimpleNamespace(width="uint16", count=1, address=0x2000, buffer=b"\x02\x00"),
            offset=0x25,
        ),
    ]

    rendered = SemanticIrRenderer().render(_raw_script(records), "", [])

    assert rendered == "mem[0x1000] <- 0x0001\nmem[0x2000] <- 0x0002\n"


def _sample_raw_script() -> RawBootScript:
    return _raw_script(
        [
            _record(
                OpcodeId.MEM_WRITE,
                SimpleNamespace(width="uint16", count=1, address=0x1000, buffer=b"\x01\x00"),
                offset=0x0D,
            )
        ]
    )


def _raw_script(records: list[RawOpcodeRecord]) -> RawBootScript:
    return RawBootScript(
        table_header=RawTableHeader(magic=0xAA, length=13, version=1, table_length=34),
        records=records,
    )


def _record(opcode_id: OpcodeId, body: object, offset: int) -> RawOpcodeRecord:
    return RawOpcodeRecord(
        opcode_id=int(opcode_id),
        length=21,
        offset=offset,
        body=body,
        raw_bytes=int(opcode_id).to_bytes(2, "little") + b"\x15" + b"\x00" * 18,
    )
