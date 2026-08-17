from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from .adapters import TraceAdapter
from .trace import TraceEvent


class SupportsTraceAudit(Protocol):
    """Minimal protocol required by audit_external_trace()."""

    def audit_events(
        self,
        events: list[TraceEvent],
        *,
        trace_path: str | Path = "<events>",
        **audit_kwargs: Any,
    ) -> Any:
        ...


def audit_external_trace(
    gate: SupportsTraceAudit,
    input_path: str | Path,
    *,
    mapping: str | Path,
    diagnostics_path: str | Path | None = None,
    **audit_kwargs: Any,
) -> Any:
    """Normalize and audit an external JSONL trace in one SDK call.

    The external trace is normalized in memory, so the resulting audit report
    keeps the original external trace path as its ``trace_path``. Adapter
    provenance, including ``external_content_path``, is preserved.

    Extra keyword arguments are forwarded to ``gate.audit_events`` so this
    helper stays aligned with the SDK audit option surface.
    """
    source = Path(input_path)
    adapter = TraceAdapter.from_mapping(mapping)
    events = adapter.load(source)

    if diagnostics_path is not None:
        diagnostics = adapter.diagnostics(source)
        output_path = Path(diagnostics_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return gate.audit_events(
        events,
        trace_path=source,
        **audit_kwargs,
    )
