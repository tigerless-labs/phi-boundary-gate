# Direct external trace audit

`v0.6.1` adds a one-step path for auditing external agent traces. It composes
the existing mapping-v1 adapter and the existing path-aware audit pipeline;
it does not introduce a new trace schema, report schema, detector, or policy
format.

## CLI

```bash
phi-boundary-gate scan-external-trace \
  --input raw-agent-events.jsonl \
  --mapping config/phi-trace-map.yml \
  --policy config/phi-policy.yml \
  --out /tmp/phi-report.md \
  --json /tmp/phi-report.json \
  --diagnostics /tmp/phi-adapter-diagnostics.json \
  --report-values redacted
```

The command:

1. loads the existing mapping-v1 adapter;
2. normalizes the external JSONL trace;
3. preserves adapter provenance including `external_content_path`;
4. runs the existing `scan-trace` audit path;
5. writes the existing schema-v3 Markdown/JSON reports.

The normalized trace is temporary by default. To retain it for adapter
debugging, add:

```bash
--normalized-trace /tmp/phi-normalized-trace.jsonl
```

The retained normalized trace can still contain sensitive content. Treat it
as a controlled debugging artifact and do not commit it.

To write the existing redacted trace artifact as well:

```bash
--redacted-trace /tmp/phi-redacted-trace.jsonl
```

## Report values

`scan-external-trace` intentionally defaults to:

```text
--report-values redacted
```

`raw`, `redacted`, and `hashed` remain available. Prefer `redacted` or
`hashed` for shareable audit artifacts.

## SDK

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()

result = gate.audit_external_trace(
    "raw-agent-events.jsonl",
    mapping="config/phi-trace-map.yml",
    diagnostics_path="/tmp/phi-adapter-diagnostics.json",
    report_value_mode="redacted",
)

result.write_json("/tmp/phi-report.json")
result.write_markdown("/tmp/phi-report.md")
```

`PhiBoundaryGate.audit_external_trace(...)` normalizes the external trace in
memory and forwards the audit options to the existing `audit_events(...)`
pipeline. The resulting report keeps the original external input path as
`trace_path`; it does not point at a deleted temporary normalized file.

The function-style `audit_external_trace(gate, ...)` export remains available
for callers that prefer composition over the facade method.

## Existing pipeline remains supported

The explicit workflow remains available for users who want to inspect or
persist every stage:

```bash
phi-boundary-gate convert-trace ...
phi-boundary-gate validate-trace ...
phi-boundary-gate scan-trace ...
```

`v0.6.1` is additive. Mapping v1, the normalized trace schema, policy schema,
report schema v3, and existing CLI commands remain unchanged.

## Diagnostics and safety

Adapter diagnostics are conversion/mapping summaries and should not be
expanded to copy raw event bodies or raw PHI. Repository tests and examples
must continue to use synthetic identifiers only.
