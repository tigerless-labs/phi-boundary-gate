from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .api import guard_text
from .policy import Policy
from .trace import TraceEvent


def redacted_trace_events(events: list[TraceEvent], policy: Policy) -> list[dict[str, Any]]:
    replacements = _trace_replacements(events, policy)
    redacted: list[dict[str, Any]] = []
    for event in events:
        decision = guard_text(event.content, event.layer, policy)
        content = _replace_known_values(decision.redacted_text, replacements)
        row: dict[str, Any] = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "layer": event.layer,
            "source": event.source,
            "destinations": event.destinations,
            "content": content,
        }
        if event.metadata:
            row["metadata"] = event.metadata
        redacted.append(row)
    return redacted


def write_redacted_trace(events: list[TraceEvent], policy: Policy, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event, sort_keys=True) for event in redacted_trace_events(events, policy)]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _trace_replacements(events: list[TraceEvent], policy: Policy) -> list[tuple[str, str]]:
    replacements: dict[str, str] = {}
    for event in events:
        decision = guard_text(event.content, event.layer, policy)
        for finding in decision.findings:
            replacements.setdefault(finding["value"], finding["redaction"]["suggested_value"])
    return sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)


def _replace_known_values(text: str, replacements: list[tuple[str, str]]) -> str:
    redacted = text
    for value, replacement in replacements:
        redacted = redacted.replace(value, replacement)
    return redacted
