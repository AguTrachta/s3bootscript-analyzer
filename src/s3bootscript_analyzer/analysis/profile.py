"""Generic immutable JSON facts supplied to analysis."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | tuple[JsonValue, ...] | Mapping[str, JsonValue]
type JsonObject = Mapping[str, JsonValue]

MAX_PROFILE_DEPTH = 64


class MissingProfileDataError(ValueError):
    """Raised when a rule requires absent top-level profile fields."""


@dataclass(frozen=True, init=False)
class AnalysisProfile:
    """Read-only JSON snapshot; field meanings belong to producers and rules."""

    name: str
    data: JsonObject

    def __init__(self, name: str, data: Mapping[str, object]) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "data", freeze_json_object(data))

    def require_fields(self, fields: tuple[str, ...]) -> None:
        """Require literal top-level keys without interpreting their values."""
        missing = tuple(name for name in fields if name not in self.data)
        if missing:
            raise MissingProfileDataError(
                f"Required profile fields are unavailable: {', '.join(missing)}"
            )


def freeze_json_object(value: Mapping[str, object]) -> JsonObject:
    """Take an immutable, recursively typed snapshot of a JSON-shaped object."""
    return _freeze_object(value, 0)


def _freeze_object(value: Mapping[str, object], depth: int) -> JsonObject:
    return MappingProxyType(
        {_string_key(key): _freeze_value(item, depth + 1) for key, item in value.items()}
    )


def _string_key(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Profile object keys must be strings")
    return value


def _freeze_value(value: object, depth: int) -> JsonValue:
    if depth > MAX_PROFILE_DEPTH:
        raise ValueError(f"Profile nesting exceeds {MAX_PROFILE_DEPTH} levels")
    if isinstance(value, Mapping):
        return _freeze_object(value, depth)
    return _freeze_sequence_or_scalar(value, depth)


def _freeze_sequence_or_scalar(value: object, depth: int) -> JsonValue:
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item, depth + 1) for item in value)
    return _scalar(value)


def _scalar(value: object) -> JsonScalar:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return _finite_number(value)
    raise ValueError(f"Unsupported profile value type: {type(value).__name__}")


def _finite_number(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError("Profile numbers must be finite")
    return value
