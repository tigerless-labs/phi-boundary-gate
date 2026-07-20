from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SUPPORTED_LAYERS = {
    "user_message",
    "rag_context",
    "tool_output",
    "model_input",
    "memory",
    "debug_log",
}

SUPPORTED_DESTINATION_LAYERS = SUPPORTED_LAYERS | {"model_provider"}


def supported_layers_text() -> str:
    return ", ".join(sorted(SUPPORTED_LAYERS))


def supported_destination_layers_text() -> str:
    return ", ".join(sorted(SUPPORTED_DESTINATION_LAYERS))


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    timestamp: str
    layer: str
    content: str
    source: dict[str, Any] = field(default_factory=dict)
    destinations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def load_trace(path: Path) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc

            events.append(_parse_event(raw, path, line_number))

    return events


def _parse_event(raw: Any, path: Path, line_number: int) -> TraceEvent:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}:{line_number}: trace event must be an object")

    missing = [field for field in ("event_id", "timestamp", "layer", "content") if field not in raw]
    if missing:
        raise ValueError(f"{path}:{line_number}: missing required field(s): {', '.join(missing)}")

    layer = _expect_str(raw["layer"], path, line_number, "layer")
    if layer not in SUPPORTED_LAYERS:
        raise ValueError(f"{path}:{line_number}: unsupported layer {layer!r}; expected one of: {supported_layers_text()}")

    source = _expect_dict(raw.get("source", {}), path, line_number, "source")
    _validate_optional_string(source, path, line_number, "source.type")
    _validate_optional_string(source, path, line_number, "source.path")

    return TraceEvent(
        event_id=_expect_str(raw["event_id"], path, line_number, "event_id"),
        timestamp=_expect_str(raw["timestamp"], path, line_number, "timestamp"),
        layer=layer,
        content=_expect_str(raw["content"], path, line_number, "content"),
        source=source,
        destinations=_expect_destinations(raw.get("destinations", []), path, line_number),
        metadata=_expect_dict(raw.get("metadata", {}), path, line_number, "metadata"),
    )


def _expect_str(value: Any, path: Path, line_number: int, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path}:{line_number}: field {field_name!r} must be a string")
    return value


def _expect_dict(value: Any, path: Path, line_number: int, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path}:{line_number}: field {field_name!r} must be an object")
    return value


def _expect_list_of_dicts(value: Any, path: Path, line_number: int, field_name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{path}:{line_number}: field {field_name!r} must be an array of objects")
    return value


def _expect_destinations(value: Any, path: Path, line_number: int) -> list[dict[str, Any]]:
    destinations = _expect_list_of_dicts(value, path, line_number, "destinations")
    for index, destination in enumerate(destinations):
        prefix = f"destinations[{index}]"
        _validate_optional_string(destination, path, line_number, f"{prefix}.path")
        if "layer" in destination:
            layer = _expect_str(destination["layer"], path, line_number, f"{prefix}.layer")
            if layer not in SUPPORTED_DESTINATION_LAYERS:
                raise ValueError(
                    f"{path}:{line_number}: unsupported destination layer {layer!r}; "
                    f"expected one of: {supported_destination_layers_text()}"
                )
    return destinations


def _validate_optional_string(value: dict[str, Any], path: Path, line_number: int, field_name: str) -> None:
    key = field_name.rsplit(".", 1)[-1]
    if key in value:
        _expect_str(value[key], path, line_number, field_name)
