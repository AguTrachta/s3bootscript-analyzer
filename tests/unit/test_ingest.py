from pathlib import Path

import pytest

from s3bootscript_analyzer.errors import BinaryLoadError
from s3bootscript_analyzer.ingest import BinarySource, FileLoader


def test_binary_source_size_returns_data_length() -> None:
    source = BinarySource(path=Path("boot-script.bin"), data=b"\x00\x01\x02")

    assert source.size() == 3


def test_file_loader_loads_binary_source(tmp_path: Path) -> None:
    input_path = tmp_path / "boot-script.bin"
    input_path.write_bytes(b"\xaa\x0d")

    source = FileLoader().load(input_path)

    assert source.path == input_path
    assert source.data == b"\xaa\x0d"
    assert source.size() == 2


def test_file_loader_wraps_missing_file_errors(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.bin"

    with pytest.raises(BinaryLoadError) as exc_info:
        FileLoader().load(missing_path)

    assert "Unable to load input binary" in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, OSError)
