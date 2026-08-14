# Migration to 0.6.0

Version 0.6.0 promotes the package from text guard utilities plus CLI reports to
a path-aware audit toolkit for external projects.

## What Changed

- Top-level package version is `0.6.0`.
- Recommended dependency range is `phi-boundary-gate>=0.6,<0.7`.
- JSON reports now write `schema_version: 3`.
- Reports include `finding_schema: "path-aware"`.
- Findings include `content_path` and `external_content_path`.
- Boundary exposures include `content_paths_seen` and
  `external_content_paths_seen`.
- New public audit helpers are exported:
  `AuditResult`, `audit_events()`, `audit_trace()`,
  `PhiBoundaryGate.audit_events()`, and `PhiBoundaryGate.audit_trace()`.

## Compatibility

Plain text traces remain compatible. Their findings set `content_path` to
`null`, and detector spans keep the same meaning as before.

Structured event content is more precise. If an event `content` field contains a
JSON object or array encoded as a string, the scanner walks scalar leaves and
records paths such as `$.member_id` or `$.messages[0].content`. In those cases,
`span` is relative to the scanned scalar leaf.

Consumers that validate report JSON should accept the new schema fields before
upgrading. Consumers that only read `summary`, `findings`, or
`boundary_exposures` can usually ignore the added fields.

## Suggested Update

```text
phi-boundary-gate>=0.6,<0.7
```

For stored reports generated from approved non-synthetic traces, prefer:

```python
result = gate.audit_trace("normalized-trace.jsonl", report_value_mode="redacted")
```

or:

```python
result = gate.audit_trace("normalized-trace.jsonl", report_value_mode="hashed")
```
