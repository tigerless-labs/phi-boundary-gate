from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..exceptions import TraceMappingError
from ..trace import SUPPORTED_DESTINATION_LAYERS, SUPPORTED_LAYERS, TraceEvent, write_trace


class MappingError(TraceMappingError):
    pass


@dataclass(frozen=True)
class TraceMapping:
    raw: dict[str, Any]


@dataclass(frozen=True)
class TraceAdapter:
    """Callable adapter facade for converting external trace files."""

    mapping: TraceMapping

    @classmethod
    def from_mapping(cls, mapping_path: Path | str) -> "TraceAdapter":
        return cls(load_trace_mapping(Path(mapping_path)))

    def load(self, input_path: Path | str) -> list[TraceEvent]:
        return convert_generic_jsonl_trace(Path(input_path), self.mapping)

    def write(self, input_path: Path | str, output_path: Path | str) -> list[TraceEvent]:
        events = self.load(input_path)
        write_trace(events, Path(output_path))
        return events

    def diagnostics(self, input_path: Path | str) -> dict[str, Any]:
        return build_conversion_diagnostics(Path(input_path), self.mapping)

    def summary(self) -> dict[str, Any]:
        return mapping_summary(self.mapping)


def load_trace_mapping(path: Path) -> TraceMapping:
    with path.open("r", encoding="utf-8") as handle:
        try:
            raw = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise MappingError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise MappingError(f"{path}: mapping must be a YAML object")
    if raw.get("version") != 1:
        raise MappingError(f"{path}: mapping version must be 1")
    _validate_mapping_shape(raw, str(path))
    return TraceMapping(raw=raw)


def validate_trace_mapping(path: Path) -> TraceMapping:
    return load_trace_mapping(path)


def mapping_summary(mapping: TraceMapping) -> dict[str, Any]:
    raw = mapping.raw
    return {
        "version": raw["version"],
        "content_fields": _configured_content_fields(raw["content"]),
        "metadata_fields": _configured_metadata_fields(raw.get("metadata", {})),
        "layer_aliases": _configured_layer_aliases(raw.get("layer")),
        "destination_count": len(raw.get("destinations", []) or []),
    }


def load_external_trace(input_path: Path, mapping_path: Path) -> list[TraceEvent]:
    return convert_generic_jsonl_trace(input_path, load_trace_mapping(mapping_path))


def write_converted_trace(input_path: Path, mapping_path: Path, output_path: Path) -> list[TraceEvent]:
    events = load_external_trace(input_path, mapping_path)
    write_trace(events, output_path)
    return events


def build_conversion_diagnostics(input_path: Path, mapping: TraceMapping) -> dict[str, Any]:
    raw_events: list[dict[str, Any]] = []
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
            raw_events.append(raw)
            events.append(_convert_event(raw, mapping.raw, input_path, line_number, len(events) + 1))

    configured_content = _configured_content_field_specs(mapping.raw["content"])
    content_path_counts = _count_content_paths(events)
    return {
        "schema_version": 1,
        "external_format": "generic_jsonl",
        "input_path": str(input_path),
        "mapping_version": mapping.raw["version"],
        "total_events": len(events),
        "events_by_layer": _count_values(event.layer for event in events),
        "destination_layers": _count_values(
            str(destination["layer"])
            for event in events
            for destination in event.destinations
            if "layer" in destination
        ),
        "content_paths_used": content_path_counts,
        "optional_content_paths_never_used": [
            spec["field"]
            for spec in configured_content
            if not spec["required"] and spec["field"] not in content_path_counts
        ],
        "generated_event_id_count": _generated_event_id_count(raw_events, mapping.raw),
        "field_fallbacks": _field_fallback_counts(raw_events, mapping.raw),
    }


def write_conversion_diagnostics(input_path: Path, mapping_path: Path, output_path: Path) -> dict[str, Any]:
    diagnostics = build_conversion_diagnostics(input_path, load_trace_mapping(mapping_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return diagnostics


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
    if isinstance(event_id_spec, dict) and "fallback" in event_id_spec:
        fallback_prefix = _expect_string(event_id_spec["fallback"], "event_id.fallback")
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


def _validate_mapping_shape(mapping: dict[str, Any], source: str) -> None:
    for field_name in ("timestamp", "layer", "content"):
        if field_name not in mapping:
            raise MappingError(f"{source}: mapping must define {field_name}")
    _validate_value_spec(mapping.get("event_id"), "event_id", allow_empty=True, allow_fallback_prefix=True)
    _validate_value_spec(mapping["timestamp"], "timestamp")
    _validate_layer_spec(mapping["layer"], "layer", SUPPORTED_LAYERS)
    _validate_content_spec(mapping["content"])
    _validate_source_spec(mapping.get("source", {}))
    _validate_destinations_spec(mapping.get("destinations", []))
    _validate_metadata_spec(mapping.get("metadata", {}))


def _validate_content_spec(spec: Any) -> None:
    if isinstance(spec, str):
        _validate_field_path(spec, "content")
        return
    if not isinstance(spec, dict):
        raise MappingError("content must be a field string or object")
    if "field" in spec:
        _validate_field_path(_expect_string(spec["field"], "content.field"), "content.field")
        _validate_bool(spec.get("required", True), "content.required")
        return
    fields = spec.get("fields")
    if not isinstance(fields, list) or not fields:
        raise MappingError("content must define field or non-empty fields")
    for index, field_spec in enumerate(fields):
        if isinstance(field_spec, str):
            _validate_field_path(field_spec, f"content.fields[{index}]")
            continue
        if not isinstance(field_spec, dict):
            raise MappingError(f"content.fields[{index}] must be a field string or object")
        _validate_field_path(_expect_string(field_spec.get("field"), f"content.fields[{index}].field"), f"content.fields[{index}].field")
        label = field_spec.get("label", "")
        if label is not None and not isinstance(label, str):
            raise MappingError(f"content.fields[{index}].label must be a string")
        _validate_bool(field_spec.get("required", True), f"content.fields[{index}].required")


def _validate_source_spec(spec: Any) -> None:
    if spec is None:
        return
    if not isinstance(spec, dict):
        raise MappingError("source must be an object")
    for key in ("type", "path"):
        if key in spec:
            _validate_value_spec(spec[key], f"source.{key}", allow_empty=True)


def _validate_destinations_spec(spec: Any) -> None:
    if spec is None:
        return
    if not isinstance(spec, list):
        raise MappingError("destinations must be an array")
    for index, destination in enumerate(spec):
        if not isinstance(destination, dict):
            raise MappingError(f"destinations[{index}] must be an object")
        if "layer" in destination:
            _validate_layer_spec(destination["layer"], f"destinations[{index}].layer", SUPPORTED_DESTINATION_LAYERS)
        if "path" in destination:
            _validate_value_spec(destination["path"], f"destinations[{index}].path", allow_empty=True)


def _validate_metadata_spec(spec: Any) -> None:
    if spec is None:
        return
    if not isinstance(spec, dict):
        raise MappingError("metadata must be an object")
    include = spec.get("include", [])
    if not isinstance(include, list):
        raise MappingError("metadata.include must be an array")
    for index, item in enumerate(include):
        if isinstance(item, str):
            _validate_field_path(item, f"metadata.include[{index}]")
            continue
        if not isinstance(item, dict):
            raise MappingError(f"metadata.include[{index}] must be a field string or object")
        _validate_field_path(_expect_string(item.get("field"), f"metadata.include[{index}].field"), f"metadata.include[{index}].field")
        name = item.get("name", "")
        if name is not None and not isinstance(name, str):
            raise MappingError(f"metadata.include[{index}].name must be a string")
        _validate_bool(item.get("required", False), f"metadata.include[{index}].required")
    constants = spec.get("constants", {})
    if not isinstance(constants, dict):
        raise MappingError("metadata.constants must be an object")


def _validate_layer_spec(spec: Any, label: str, allowed_layers: set[str]) -> None:
    _validate_value_spec(spec, label)
    if isinstance(spec, dict):
        if "value" in spec:
            _validate_allowed_layer(_expect_string(spec["value"], f"{label}.value"), label, allowed_layers)
        layer_map = spec.get("map", {})
        if layer_map:
            if not isinstance(layer_map, dict):
                raise MappingError(f"{label}.map must be an object")
            for source_value, target_value in layer_map.items():
                if not isinstance(source_value, str):
                    raise MappingError(f"{label}.map keys must be strings")
                _validate_allowed_layer(_expect_string(target_value, f"{label}.map[{source_value}]"), f"{label}.map[{source_value}]", allowed_layers)


def _validate_value_spec(
    spec: Any,
    label: str,
    *,
    allow_empty: bool = False,
    allow_fallback_prefix: bool = False,
) -> None:
    if spec is None:
        if allow_empty:
            return
        raise MappingError(f"{label} is required")
    if isinstance(spec, str):
        _validate_field_path(spec, label)
        return
    if not isinstance(spec, dict):
        raise MappingError(f"{label} must be a field string or object")
    allowed_keys = {"field", "fields", "value", "default", "required", "map"}
    if allow_fallback_prefix:
        allowed_keys.add("fallback")
        allowed_keys.add("fallback_prefix")
    unknown = sorted(set(spec) - allowed_keys)
    if unknown:
        raise MappingError(f"{label} has unsupported key(s): {', '.join(unknown)}")
    if "field" in spec and "fields" in spec:
        raise MappingError(f"{label} must not define both field and fields")
    if "field" in spec:
        _validate_field_path(_expect_string(spec["field"], f"{label}.field"), f"{label}.field")
    if "fields" in spec:
        fields = spec["fields"]
        if not isinstance(fields, list) or not fields:
            raise MappingError(f"{label}.fields must be a non-empty array")
        for index, field in enumerate(fields):
            _validate_field_path(_expect_string(field, f"{label}.fields[{index}]"), f"{label}.fields[{index}]")
    if "field" not in spec and "fields" not in spec and "value" not in spec and "default" not in spec and not allow_empty:
        raise MappingError(f"{label} must define field, fields, value, or default")
    if "value" in spec:
        _expect_string(spec["value"], f"{label}.value")
    if "default" in spec:
        _expect_string(spec["default"], f"{label}.default")
    if "fallback_prefix" in spec:
        _expect_string(spec["fallback_prefix"], f"{label}.fallback_prefix")
    if "fallback" in spec:
        _expect_string(spec["fallback"], f"{label}.fallback")
    _validate_bool(spec.get("required", True), f"{label}.required")


def _validate_allowed_layer(value: str, label: str, allowed_layers: set[str]) -> None:
    if value not in allowed_layers:
        allowed = ", ".join(sorted(allowed_layers))
        raise MappingError(f"{label} maps to unsupported layer {value!r}; expected one of: {allowed}")


def _validate_bool(value: Any, label: str) -> None:
    if not isinstance(value, bool):
        raise MappingError(f"{label} must be a boolean")


def _validate_field_path(path: str, label: str) -> None:
    if not path:
        raise MappingError(f"{label} must not be empty")
    for part in path.split("."):
        if not part:
            raise MappingError(f"{label} has an empty path segment")


def _configured_content_fields(spec: Any) -> list[str]:
    if isinstance(spec, str):
        return [spec]
    if not isinstance(spec, dict):
        return []
    if "field" in spec:
        return [str(spec["field"])]
    return [
        field_spec if isinstance(field_spec, str) else str(field_spec.get("field", ""))
        for field_spec in spec.get("fields", [])
    ]


def _configured_content_field_specs(spec: Any) -> list[dict[str, Any]]:
    if isinstance(spec, str):
        return [{"field": spec, "required": True}]
    if not isinstance(spec, dict):
        return []
    if "field" in spec:
        return [{"field": str(spec["field"]), "required": bool(spec.get("required", True))}]
    configured: list[dict[str, Any]] = []
    for field_spec in spec.get("fields", []):
        if isinstance(field_spec, str):
            configured.append({"field": field_spec, "required": True})
        elif isinstance(field_spec, dict):
            configured.append({"field": str(field_spec.get("field", "")), "required": bool(field_spec.get("required", True))})
    return configured


def _configured_metadata_fields(spec: Any) -> list[str]:
    if not isinstance(spec, dict):
        return []
    fields: list[str] = []
    for item in spec.get("include", []):
        if isinstance(item, str):
            fields.append(item)
        elif isinstance(item, dict) and "field" in item:
            fields.append(str(item["field"]))
    return fields


def _configured_layer_aliases(spec: Any) -> dict[str, str]:
    if not isinstance(spec, dict) or not isinstance(spec.get("map"), dict):
        return {}
    return {str(key): str(value) for key, value in spec["map"].items()}


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
    if "field" not in spec and "fields" not in spec:
        default = spec.get("default", fallback)
        if default is None:
            return None
        return _expect_string(default, f"{label}.default")
    if "fields" in spec:
        value = _value_from_fields(raw, spec, input_path, line_number, label)
        if value is not None:
            return value
        default = spec.get("default")
        if default is not None:
            return _expect_string(default, f"{label}.default")
        if fallback is not None:
            return fallback
        if spec.get("required", True):
            fields = ", ".join(repr(field) for field in spec["fields"])
            raise MappingError(f"{input_path}:{line_number}: missing any field for {label}: {fields}")
        return None
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


def _value_from_fields(
    raw: dict[str, Any],
    spec: dict[str, Any],
    input_path: Path,
    line_number: int,
    label: str,
) -> str | None:
    fields = spec["fields"]
    if not isinstance(fields, list) or not fields:
        raise MappingError(f"{label}.fields must be a non-empty array")
    for index, candidate in enumerate(fields):
        field = _expect_string(candidate, f"{label}.fields[{index}]")
        try:
            value = _value_at(raw, field, input_path, line_number, label)
        except MappingError:
            continue
        text = _string_from_value(value, input_path, line_number, label)
        if text:
            return text
    return None


def _count_content_paths(events: list[TraceEvent]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        paths = event.metadata.get("external_content_paths", [])
        if not isinstance(paths, list):
            continue
        for path in paths:
            if isinstance(path, str):
                counts[path] = counts.get(path, 0) + 1
    return dict(sorted(counts.items()))


def _count_values(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _generated_event_id_count(raw_events: list[dict[str, Any]], mapping: dict[str, Any]) -> int:
    event_id_spec = mapping.get("event_id")
    return sum(1 for raw in raw_events if _selected_value_source(raw, event_id_spec, "event_id") == "<generated>")


def _field_fallback_counts(raw_events: list[dict[str, Any]], mapping: dict[str, Any]) -> dict[str, dict[str, int]]:
    specs = _diagnostic_value_specs(mapping)
    fallback_counts: dict[str, dict[str, int]] = {}
    for label, spec in specs:
        counts: dict[str, int] = {}
        for raw in raw_events:
            selected = _selected_value_source(raw, spec, label)
            if selected is not None:
                counts[selected] = counts.get(selected, 0) + 1
        if counts:
            fallback_counts[label] = dict(sorted(counts.items()))
    return dict(sorted(fallback_counts.items()))


def _diagnostic_value_specs(mapping: dict[str, Any]) -> list[tuple[str, Any]]:
    specs: list[tuple[str, Any]] = [
        ("event_id", mapping.get("event_id")),
        ("timestamp", mapping.get("timestamp")),
        ("layer", mapping.get("layer")),
    ]
    source = mapping.get("source", {})
    if isinstance(source, dict):
        for key in ("type", "path"):
            if key in source:
                specs.append((f"source.{key}", source[key]))
    destinations = mapping.get("destinations", [])
    if isinstance(destinations, list):
        for index, destination in enumerate(destinations):
            if not isinstance(destination, dict):
                continue
            for key in ("layer", "path"):
                if key in destination:
                    specs.append((f"destinations[{index}].{key}", destination[key]))
    return specs


def _selected_value_source(raw: dict[str, Any], spec: Any, label: str) -> str | None:
    if spec is None:
        return "<generated>" if label == "event_id" else None
    if isinstance(spec, str):
        return spec if _can_read_value(raw, spec) else None
    if not isinstance(spec, dict):
        return None
    if "value" in spec:
        return "<value>"
    if "field" in spec:
        field = str(spec["field"])
        if _can_read_value(raw, field):
            return field
    if "fields" in spec and isinstance(spec["fields"], list):
        for candidate in spec["fields"]:
            if isinstance(candidate, str) and _can_read_value(raw, candidate):
                return candidate
    if "default" in spec:
        return "<default>"
    if label == "event_id":
        return "<generated>"
    return None


def _can_read_value(raw: dict[str, Any], field: str) -> bool:
    current: Any = raw
    for part in field.split("."):
        if isinstance(current, dict):
            if part not in current:
                return False
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return False
            current = current[index]
            continue
        return False
    return current not in (None, "")


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
