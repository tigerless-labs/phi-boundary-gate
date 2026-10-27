# Audit Coverage Diagnostics

v0.8.3 adds an opt-in, deterministic summary of the normalized trace events
that were available to the scanner. Coverage output is separate from Audit
Report schema v3 and is always advisory.

## CLI

```bash
phi-boundary-gate scan-trace \
  --trace samples/traces/no_phi.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-report.md \
  --json /tmp/phi-report.json \
  --coverage-json /tmp/phi-coverage.json \
  --coverage-markdown /tmp/phi-coverage.md \
  --expect-layer model_input \
  --expect-layer tool_output
```

The same three coverage options are available on `scan-external-trace`.
`--expect-layer` is repeatable and accepts only normalized trace layers. A
missing-layer diagnostic is emitted only for a layer the caller explicitly
declared. Omitting all coverage output options preserves the existing command,
report, stdout, and exit behavior.

For a valid trace, coverage warnings never make the command fail. Invalid JSONL,
invalid mappings or policies, unsupported arguments, code errors, and output
write failures still fail normally.

## Coverage JSON v1

The JSON output has `schema_version: 1` and these top-level fields:

- `summary`: event, content-segment, structure, source, and destination counts.
- `observed_layers`: sorted normalized layers present in the input.
- `expected_layers`: sorted caller-supplied expectations.
- `diagnostics`: bounded advisory warnings with fixed reason codes.
- `mapping`: optional aggregate mapping evidence for external traces.
- `interpretation`: fixed text describing the semantic limits.

The summary fields are:

- `observed_event_count`
- `events_by_layer`
- `empty_content_event_count`
- `nonempty_content_event_count`
- `scannable_segment_count`
- `structured_content_event_count`
- `structured_content_without_scalar_event_count`
- `events_with_source_count`
- `events_with_destinations_count`
- `provider_destination_event_count`

Event counts, content segment counts, and finding counts are different units.
Coverage never treats a no-finding event as PHI-free. Structured JSON reuses the
scanner's scalar-leaf traversal; an empty object, empty array, or structure with
only empty/null leaves has no scannable scalar segment.

## Diagnostic Reason Codes

- `EMPTY_TRACE`: no normalized events were observed.
- `EMPTY_CONTENT_EVENTS`: one or more events had no scannable plain-text or
  structured scalar content.
- `EXPECTED_LAYER_NOT_OBSERVED`: an explicitly expected layer was absent.
- `NO_EXPLICIT_DESTINATIONS`: no observed event declared any destination.
- `NO_PROVIDER_DESTINATION_OBSERVED`: destinations were present, but none used
  the `model_provider` sink.
- `MAPPING_OPTIONAL_CONTENT_UNUSED`: aggregate adapter evidence shows that one
  or more optional mapped content fields were unused.
- `COVERAGE_UNVERIFIED`: no expected layers were supplied, so execution-stage
  completeness was not checked.

These codes describe observed evidence. A missing destination is not necessarily
an error, and the absence of `model_provider` does not prove whether an external
provider call happened. Optional mapping fields may be legitimately unused.
Coverage never invents a dropped-event count.

## SDK

```python
from phi_boundary_gate import PhiBoundaryGate, build_audit_coverage, load_trace

events = load_trace("trace.jsonl")
coverage = build_audit_coverage(
    events,
    expected_layers=["model_input", "tool_output"],
)

coverage.write_json("coverage.json")
coverage.write_markdown("coverage.md")

gate = PhiBoundaryGate.from_policy_file("policy.yml")
same_coverage = gate.coverage_events(
    events,
    expected_layers=["model_input", "tool_output"],
)
```

The facade also provides `coverage_trace(...)` and
`coverage_external_trace(...)`. External coverage derives optional-content
mapping evidence from the already normalized in-memory events rather than
rereading the external trace.

A runnable version is available at
[`examples/sdk_audit_coverage.py`](../examples/sdk_audit_coverage.py).

## Safety and Interpretation

Coverage JSON and Markdown contain only aggregate integers, normalized layer
enums, fixed reason codes, and fixed explanatory text. They do not copy trace
content, event IDs, source/destination paths, input file paths, external JSON
keys, findings, or raw PHI.

Three boundaries are fundamental:

1. Observed Coverage is not proof of actual Agent Execution Completeness.
2. Zero Findings does not prove that no PHI existed.
3. A Coverage Warning is not a HIPAA Noncompliance determination.

Coverage JSON v1 can also be compared as optional evidence beside Exposure Diff.
That v0.8.4 operation consumes these summaries directly and does not rescan the
trace. See [Coverage-Aware Exposure Diff](coverage-aware-exposure-diff.md).

No LLM, network service, or new runtime dependency is used.
