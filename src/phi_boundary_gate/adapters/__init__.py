"""Adapters for normalizing external agent traces into PHI Boundary Gate events."""

from .generic_jsonl import (
    TraceAdapter,
    TraceMapping,
    convert_generic_jsonl_trace,
    load_external_trace,
    load_trace_mapping,
    mapping_summary,
    validate_trace_mapping,
    write_converted_trace,
)

__all__ = [
    "TraceAdapter",
    "TraceMapping",
    "convert_generic_jsonl_trace",
    "load_external_trace",
    "load_trace_mapping",
    "mapping_summary",
    "validate_trace_mapping",
    "write_converted_trace",
]
