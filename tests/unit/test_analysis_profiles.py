"""Producer JSON is directly consumable without domain-specific adaptation."""

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisProfile,
    MissingProfileDataError,
    ProfileSelection,
)
from s3bootscript_analyzer.profile_data import (
    JsonProfileLoader,
    JsonProfileWriter,
    PlatformProfile,
    ProfileDiagnostic,
    ProfileLoadError,
    ProfileRange,
)


def test_generated_json_loads_without_conversion_and_preserves_provenance(tmp_path: Path) -> None:
    path = tmp_path / "kernel.json"
    producer = PlatformProfile(
        source="proc_iomem_kernel",
        ranges=[ProfileRange("KERNEL_CODE_RANGE", 4096, 8191, "Kernel code")],
        diagnostics=[ProfileDiagnostic("warning", "Partial collection")],
    )
    JsonProfileWriter().write(producer, path)

    profile = JsonProfileLoader().load(ProfileSelection(path))

    assert profile.name == "kernel.json"
    assert profile.data == {
        "source": "proc_iomem_kernel",
        "ranges": (
            {
                "name": "KERNEL_CODE_RANGE",
                "start": 4096,
                "end": 8191,
                "source_label": "Kernel code",
            },
        ),
        "diagnostics": ({"level": "warning", "message": "Partial collection"},),
        "schema_version": 1,
    }


def test_non_memory_profile_needs_no_schema_registration(tmp_path: Path) -> None:
    path = tmp_path / "configuration.json"
    facts = {
        "schema_version": 23,
        "limits": {"maximum_count": 128},
        "allowed_identifiers": ["alpha", "beta"],
        "features": {"auditing_required": True},
        "note": None,
        "ratio": 1.5,
    }
    path.write_text(json.dumps(facts), encoding="utf-8")

    profile = JsonProfileLoader().load(ProfileSelection(path))

    profile.require_fields(("limits", "allowed_identifiers", "features"))
    assert profile.data["limits"] == {"maximum_count": 128}
    assert profile.data["allowed_identifiers"] == ("alpha", "beta")
    assert profile.data["schema_version"] == 23
    assert profile.data["features"] == {"auditing_required": True}


def test_profile_is_an_independent_deeply_immutable_snapshot() -> None:
    nested = {"maximum": 128}
    items = [nested]
    profile = AnalysisProfile(name="test", data={"items": items})
    nested["maximum"] = 0
    items.clear()

    assert profile.data["items"] == ({"maximum": 128},)
    with pytest.raises(TypeError):
        profile.data["extra"] = 1  # type: ignore[index]
    frozen_items = profile.data["items"]
    assert isinstance(frozen_items, tuple)
    frozen_item = frozen_items[0]
    assert isinstance(frozen_item, Mapping)
    with pytest.raises(TypeError):
        frozen_item["maximum"] = 0


def test_default_has_no_invented_facts() -> None:
    profile = JsonProfileLoader().load(ProfileSelection())

    assert profile.name == "default"
    assert profile.data == {}
    with pytest.raises(MissingProfileDataError, match="ranges, limits"):
        profile.require_fields(("ranges", "limits"))


def test_required_fields_check_presence_instead_of_truthiness_or_paths() -> None:
    profile = AnalysisProfile(
        name="test", data={"ranges": [], "flag": False, "count": 0, "note": None, "a.b": 1}
    )

    profile.require_fields(("ranges", "flag", "count", "note", "a.b"))
    with pytest.raises(MissingProfileDataError, match="a"):
        profile.require_fields(("a",))


@pytest.mark.parametrize(
    "text",
    [
        "{",
        "[]",
        "null",
        "1",
        '"text"',
        '{"count": 1, "count": 2}',
        '{"nested": {"key": 1, "key": 2}}',
        '{"value": NaN}',
        '{"value": Infinity}',
        '{"value": -Infinity}',
        '{"value": 1e999}',
        '{"value": 0xff}',
        "name: yaml-is-not-json",
        '{"nested":' + "[" * 70 + "0" + "]" * 70 + "}",
    ],
)
def test_invalid_explicit_profile_never_falls_back_to_default(tmp_path: Path, text: str) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ProfileLoadError, match="invalid.json"):
        JsonProfileLoader().load(ProfileSelection(path))


def test_unreadable_explicit_profile_reports_its_path(tmp_path: Path) -> None:
    with pytest.raises(ProfileLoadError, match="missing.json"):
        JsonProfileLoader().load(ProfileSelection(tmp_path / "missing.json"))


def test_invalid_utf8_profile_is_a_load_error(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(b"\xff")

    with pytest.raises(ProfileLoadError, match="invalid.json"):
        JsonProfileLoader().load(ProfileSelection(path))


def test_large_json_integers_keep_their_exact_value(tmp_path: Path) -> None:
    path = tmp_path / "integer.json"
    path.write_text('{"value": 18446744073709551615}', encoding="utf-8")

    profile = JsonProfileLoader().load(ProfileSelection(path))

    assert isinstance(profile.data["value"], int)
    assert profile.data["value"] == 18446744073709551615


@pytest.mark.parametrize("value", [object(), {1, 2}, float("nan"), {1: "invalid key"}])
def test_programmatic_profiles_reject_non_json_values(value: object) -> None:
    with pytest.raises(ValueError):
        AnalysisProfile(name="test", data={"value": value})


@pytest.mark.parametrize(
    "path", sorted((Path(__file__).resolve().parents[2] / "profiles").rglob("*.json"))
)
def test_repository_profile_examples_load(path: Path) -> None:
    profile = JsonProfileLoader().load(ProfileSelection(path))

    assert profile.name == path.name
