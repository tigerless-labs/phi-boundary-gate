# External Integration

Use this package as an installed dependency in the calling project. Do not copy
source files or import private modules.

## Recommended Flow

1. Install `phi-boundary-gate>=0.6,<0.7`.
2. Run `phi-boundary-gate init` in the consuming project.
3. Review `config/phi-policy.yml` and, if needed,
   `config/phi-compliance-policy.yml`.
4. Normalize raw agent logs with `TraceAdapter` or the `convert-trace` CLI.
5. Run `PhiBoundaryGate.audit_trace()` or `PhiBoundaryGate.audit_events()`.
6. Store reports with `report_value_mode="redacted"` or `"hashed"` unless the
   storage location is approved for raw PHI.

## In-Process Audit

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()
result = gate.audit_trace("normalized-trace.jsonl", report_value_mode="redacted")

if result.has_violations:
    raise RuntimeError("PHI boundary violation candidates found")

result.write_json("phi-report.json")
result.write_markdown("phi-report.md")
```

## Adapter to Audit

```python
from phi_boundary_gate import PhiBoundaryGate, TraceAdapter

adapter = TraceAdapter.from_mapping("config/phi-trace-map.yml")
events = adapter.load("raw-agent-events.jsonl")

gate = PhiBoundaryGate.from_project()
result = gate.audit_events(events, trace_path="raw-agent-events.jsonl", report_value_mode="hashed")
```

Adapter metadata can include `external_content_paths`. When an event contains
structured JSON content, report schema v3 combines a single external base path
with the structured content path so findings can be traced back to raw payload
fields.

## Operational Notes

- Keep real PHI out of source control.
- Treat detector matches as PHI candidates that still need review.
- Prefer `AuditResult.to_dict()` for service-to-service handoff and
  `AuditResult.to_markdown()` for human review.
- Catch `PhiBoundaryGateError` for package validation failures and
  `TraceMappingError` for external trace conversion failures.
