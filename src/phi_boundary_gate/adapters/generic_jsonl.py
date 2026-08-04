from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..trace import SUPPORTED_DESTINATION_LAYERS, SUPPORTED_LAYERS, TraceEvent, write_trace


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class TraceMapping:
    raw: dict[str, Any]


def load_trace_mapping(path: Path) -> TraceMapping:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise MappingError(f"{path}: mapping must be a YAML object")
    if raw.get("version") != 1:
        raise MappingError(f"{path}: mapping version must be 1")
    return TraceMapping(raw=raw)


def load_external_trace(input_path: Path, mapping_path: Path) -> list[TraceEvent]:
    return convert_generic_jsonl_trace(input_path, load_trace_mapping(mapping_path))


def write_converted_trace(input_path: Path, mapping_path: Path, output_path: Path) -> list[TraceEvent]:
    events = load_external_trace(input_path, mapping_path)
    write_trace(events, output_path)
    return events


def convert_generic_jsonl_trace(input_path: Path, mapping: TraceMapping) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise MappingError(f"{input_path}:{line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(raw, dict):
                raise MappingError(f"{input_path}:{line_number}: input event must be an object")
            events.append(_convert_event(raw, mapping.raw, input_path, line_number, len(events) + 1))
    return events


def _convert_event(
    raw: dict[str, Any],
    mapping: dict[str, Any],
    input_path: Path,
    line_number: int,
    event_number: int,
) -> TraceEvent:
    event_id_spec = mapping.get("event_id")
    fallback_prefix = "external_evt"
    if isinstance(event_id_spec, dict) and "fallback_prefix" in event_id_spec:
        fallback_prefix = _expect_string(event_id_spec["fallback_prefix"], "event_id.fallback_prefix")
    event_id = _string_value(
        raw,
        event_id_spec,
        input_path,
        line_number,
        "event_id",
        fallback=f"{fallback_prefix}_{event_number:04d}",
    )
    timestamp = _string_value(raw, mapping.get("timestamp"), input_path, line_number, "timestamp")
    layer = _layer_value(raw, mapping.get("layer"), input_path, line_number, "layer", SUPPORTED_LAYERS)
    content, content_paths = _content_value(raw, mapping.get("content"), input_path, line_number)
    source = _source_value(raw, mapping.get("source", {}), input_path, line_number)
    destinations = _destinations_value(raw, mapping.get("destinations", []), input_path, line_number)
    metadata = _metadata_value(raw, mapping.get("metadata", {}), input_path, line_number)
    if content_paths:
        metadata.setdefault("external_content_paths", content_paths)
    metadata.setdefault("external_format", "generic_jsonl")
    metadata.setdefault("external_line_number", line_number)

    return TraceEvent(
        event_id=event_id,
        timestamp=timestamp,
        layer=layer,
        content=content,
        source=source,
        destinations=destinations,
        metadata=metadata,
    )


def _content_value(
    raw: dict[str, Any],
    spec: Any,
    input_path: Path,
    line_number: int,
) -> tuple[str, list[str]]:
    if spec is None:
        raise MappingError("mapping must define content")
    if isinstance(spec, str):
        value = _value_at(raw, spec, input_path, line_number, "content")
        return _content_text(value), [spec]
    if not isinstance(spec, dict):
        raise MappingError("mapping content must be a field string or object")

    if "field" in spec:
        field = _expect_string(spec["field"], "content.field")
        value = _value_at(raw, field, input_path, line_number, "content")
        return _content_text(value), [field]

    fields = spec.get("fields")
    if not isinstance(fields, list) or not fields:
        raise MappingError("mapping content must define field or non-empty fields")

    parts: list[str] = []
    paths: list[str] = []
    for index, field_spec in enumerate(fields):
        field, label, required = _content_field_spec(field_spec, index)
        try:
            value = _value_at(raw, field, input_path, line_number, f"content.fields[{index}]")
        except MappingError:
            if required:
                raise
            continue
        text = _content_text(value)
        if not text:
            continue
        paths.append(field)
        parts.append(f"{label}: {text}" if label else text)

    if not parts:
        raise MappingError(f"{input_path}:{line_number}: no content fields produced text")
    return "\n".join(parts), paths


def _content_field_spec(spec: Any, index: int) -> tuple[str, str, bool]:
    if isinstance(spec, str):
        return spec, spec, True
    if not isinstance(spec, dict):
        raise MappingError(f"content.fields[{index}] must be a field string or object")
    field = _expect_string(spec.get("field"), f"content.fields[{index}].field")
    label = spec.get("label", field)
    if label is not None and not isinstance(label, str):
        raise MappingError(f"content.fields[{index}].label must be a string")
    required = spec.get("required", True)
    if not isinstance(required, bool):
        raise MappingError(f"content.fields[{index}].required must be a boolean")
    return field, label or "", required


def _source_value(raw: dict[str, Any], spec: Any, input_path: Path, line_number: int) -> dict[str, Any]:
    if spec is None:
        return {}
    if not isinstance(spec, dict):
        raise MappingError("mapping source must be an object")
    source: dict[str, Any] = {}
    for key in ("type", "path"):
        if key in spec:
            value = _optional_string_value(raw, spec[key], input_path, line_number, f"source.{key}")
            if value:
                source[key] = value
    return source


def _destinations_value(raw: dict[str, Any], spec: Any, input_path: Path, line_number: int) -> list[dict[str, Any]]:
    if spec is None:
        return []
    if not isinstance(spec, list):
        raise MappingError("mapping destinations must be an array")
    destinations: list[dict[str, Any]] = []
    for index, destination_spec in enumerate(spec):
        if not isinstance(destination_spec, dict):
            raise MappingError(f"destinations[{index}] must be an object")
        destination: dict[str, Any] = {}
        if "layer" in destination_spec:
            layer = _optional_layer_value(
                raw,
                destination_spec["layer"],
                input_path,
                line_number,
                f"destinations[{index}].layer",
                SUPPORTED_DESTINATION_LAYERS,
            )
            if layer is None:
                continue
            destination["layer"] = layer
        if "path" in destination_spec:
            path = _optional_string_value(raw, destination_spec["path"], input_path, line_number, f"destinations[{index}].path")
            if path:
                destination["path"] = path
        if destination:
            destinations.append(destination)
    return destinations


def _metadata_value(raw: dict[str, Any], spec: Any, input_path: Path, line_number: int) -> dict[str, Any]:
    if spec is None:
        return {}
    if not isinstance(spec, dict):
        raise MappingError("mapping metadata must be an object")
    metadata: dict[str, Any] = {}
    include = spec.get("include", [])
    if not isinstance(include, list):
        raise MappingError("metadata.include must be an array")
    for item in include:
        if isinstance(item, str):
            field = item
            name = item
            required = False
        elif isinstance(item, dict):
            field = _expect_string(item.get("field"), "metadata.include[].field")
            name = item.get("name", field)
            if not isinstance(name, str):
                raise MappingError("metadata.include[].name must be a string")
            required = item.get("required", False)
            if not isinstance(required, bool):
                raise MappingError("metadata.include[].required must be a boolean")
        else:
            raise MappingError("metadata.include entries must be field strings or objects")
        try:
            metadata[name] = _value_at(raw, field, input_path, line_number, f"metadata.{name}")
        except MappingError:
            if required:
                raise
    constants = spec.get("constants", {})
    if not isinstance(constants, dict):
        raise MappingError("metadata.constants must be an object")
    metadata.update(constants)
    return metadata


def _layer_value(
    raw: dict[str, Any],
    spec: Any,
    input_path: Path,
    line_number: int,
    label: str,
    allowed_layers: set[str],
) -> str:
    raw_value = _string_value(raw, spec, input_path, line_number, label)
    layer_map = spec.get("map", {}) if isinstance(spec, dict) else {}
    if layer_map:
        if not isinstance(layer_map, dict):
            raise MappingError(f"{label}.map must be an object")
        raw_value = str(layer_map.get(raw_value, raw_value))
    if raw_value not in allowed_layers:
        allowed = ", ".join(sorted(allowed_layers))
        raise MappingError(f"{input_path}:{line_number}: {label} mapped to unsupported layer {raw_value!r}; expected one of: {allowed}")
    return raw_value


def _optional_layer_value(
    raw: dict[str, Any],
    spec: Any,
    input_path: Path,
    line_number: int,
    label: str,
    allowed_layers: set[str],
) -> str | None:
    raw_value = _optional_string_value(raw, spec, input_path, line_number, label)
    if raw_value is None or raw_value == "":
        return None
    layer_map = spec.get("map", {}) if isinstance(spec, dict) else {}
    if layer_map:
        if not isinstance(layer_map, dict):
            raise MappingError(f"{label}.map must be an object")
        raw_value = str(layer_map.get(raw_value, raw_value))
    if raw_value not in allowed_layers:
        allowed = ", ".join(sorted(allowed_layers))
        raise MappingError(f"{input_path}:{line_number}: {label} mapped to unsupported layer {raw_value!r}; expected one of: {allowed}")
    return raw_value


def _string_value(
    raw: dict[str, Any],
    spec: Any,
    input_path: Path,
    line_number: int,
    label: str,
    *,
    fallback: str | None = None,
) -> str:
    value = _optional_string_value(raw, spec, input_path, line_number, label, fallback=fallback)
    if value is None or value == "":
        raise MappingError(f"{input_path}:{line_number}: {label} is required")
    return value


def _optional_string_value(
    raw: dict[str, Any],
    spec: Any,
    input_path: Path,
    line_number: int,
    label: str,
    *,
    fallback: str | None = None,
) -> str | None:
    if spec is None:
        return fallback
    if isinstance(spec, str):
        return _string_from_value(_value_at(raw, spec, input_path, line_number, label), input_path, line_number, label)
    if not isinstance(spec, dict):
        raise MappingError(f"{label} mapping must be a field string or object")
    if "value" in spec:
        return _expect_string(spec["value"], f"{label}.value")
    if "field" not in spec:
        default = spec.get("default", fallback)
        if default is None:
            return None
        return _expect_string(default, f"{label}.default")
    field = _expect_string(spec["field"], f"{label}.field")
    required = spec.get("required", True)
    if not isinstance(required, bool):
        raise MappingError(f"{label}.required must be a boolean")
    try:
        value = _value_at(raw, field, input_path, line_number, label)
    except MappingError:
        default = spec.get("default")
        if default is not None:
            return _expect_string(default, f"{label}.default")
        if fallback is not None:
            return fallback
        if required:
            raise
        if default is None:
            return None
    return _string_from_value(value, input_path, line_number, label)


def _value_at(raw: dict[str, Any], field: str, input_path: Path, line_number: int, label: str) -> Any:
    current: Any = raw
    for part in field.split("."):
        if part == "":
            raise MappingError(f"{label}: empty path segment in {field!r}")
        if isinstance(current, dict):
            if part not in current:
                raise MappingError(f"{input_path}:{line_number}: missing field {field!r} for {label}")
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                raise MappingError(f"{input_path}:{line_number}: list index {index} out of range for {label}")
            current = current[index]
            continue
        raise MappingError(f"{input_path}:{line_number}: cannot read {field!r} for {label}")
    return current


def _content_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def _string_from_value(value: Any, input_path: Path, line_number: int, label: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    raise MappingError(f"{input_path}:{line_number}: {label} must resolve to a string or scalar")


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise MappingError(f"{label} must be a string")
    return value
