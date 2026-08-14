from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ContentSegment:
    path: str | None
    text: str


def content_segments(content: str) -> list[ContentSegment]:
    """Return scan-ready text segments with optional JSON leaf paths."""
    parsed = _parse_json_container(content)
    if parsed is None:
        return [ContentSegment(path=None, text=content)]

    segments = list(_leaf_segments(parsed, "$"))
    return segments or [ContentSegment(path=None, text=content)]


def _parse_json_container(content: str) -> Any | None:
    stripped = content.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    return None


def _leaf_segments(value: Any, path: str) -> list[ContentSegment]:
    if isinstance(value, dict):
        segments: list[ContentSegment] = []
        for key, item in value.items():
            if not isinstance(key, str):
                continue
            segments.extend(_leaf_segments(item, f"{path}.{key}"))
        return segments
    if isinstance(value, list):
        segments = []
        for index, item in enumerate(value):
            segments.extend(_leaf_segments(item, f"{path}[{index}]"))
        return segments
    if value is None:
        return []
    if isinstance(value, str):
        text = value
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    else:
        return []
    if not text:
        return []
    return [ContentSegment(path=path, text=text)]


def external_content_path(base_paths: Any, content_path: str | None) -> str | None:
    if not isinstance(base_paths, list) or len(base_paths) != 1 or not isinstance(base_paths[0], str):
        return None
    base = base_paths[0]
    if content_path is None:
        return base
    if content_path == "$":
        return base
    if content_path.startswith("$."):
        return f"{base}.{content_path[2:]}"
    if content_path.startswith("$["):
        return f"{base}{content_path[1:]}"
    return None
