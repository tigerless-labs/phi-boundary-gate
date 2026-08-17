# Library API

The package can be imported by other Python projects that need lightweight PHI
candidate scanning, policy decisions, redaction, model-call guard checks, or
path-aware trace audit reports.

## Load Policy

```python
from pathlib import Path

from phi_boundary_gate import load_policy

policy = load_policy(Path("config/phi-policy.yml"))
```

The consuming project owns this policy file. The sample policies in this
repository are examples to copy and adapt; they are not installed as package data.

## Project SDK Facade

For application integration, initialize the consuming project once:

```bash
phi-boundary-gate init
phi-boundary-gate check-config
```

Then load the project config through the SDK facade:

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()

decision = gate.guard_model_input("member_id=MBR-SYN-8842")
if decision.should_block:
    raise RuntimeError(decision.recommended_action)

safe_log_text = gate.redact_for_log("debug member_id=MBR-SYN-8842")
audit_payload = decision.to_safe_dict()
```

`from_project()` discovers `.phi-boundary-gate/config.json` by walking upward
from the current working directory. The config points to the consuming project's
PHI policy and optional compliance policy.

## Trace Audit SDK

Use `PhiBoundaryGate.audit_trace()` when another service already has a normalized
trace JSONL file:

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()
result = gate.audit_trace("normalized-trace.jsonl", report_value_mode="redacted")

if result.has_violations:
    raise RuntimeError("PHI boundary violation candidates found")

result.write_json("phi-report.json")
result.write_markdown("phi-report.md")
payload = result.to_dict()
```

Use `PhiBoundaryGate.audit_events()` when the calling project already has
`TraceEvent` objects in memory:

```python
from phi_boundary_gate import PhiBoundaryGate, TraceEvent

gate = PhiBoundaryGate.from_project()
events = [
    TraceEvent(
        event_id="evt_001",
        timestamp="2026-08-14T10:00:00Z",
        layer="tool_output",
        content='{"member_id":"MBR-SYN-8842"}',
        metadata={"external_content_paths": ["payload"]},
    )
]

result = gate.audit_events(events, report_value_mode="hashed")
assert result.findings[0]["content_path"] == "$.member_id"
assert result.findings[0]["external_content_path"] == "payload.member_id"
```

Function-style helpers are available when callers manage policy loading
themselves:

```python
from pathlib import Path

from phi_boundary_gate import audit_trace, load_policy

policy = load_policy(Path("config/phi-policy.yml"))
result = audit_trace(
    "normalized-trace.jsonl",
    policy,
    policy_path="config/phi-policy.yml",
    report_value_mode="redacted",
)
```

`AuditResult` wraps the report dictionary and exposes `summary`, `findings`,
`boundary_exposures`, `has_findings`, `has_violations`, `to_dict()`,
`to_markdown()`, `write_json()`, and `write_markdown()`.

## Stable Exceptions

Package-level validation and integration errors inherit from
`PhiBoundaryGateError`, which also inherits from `ValueError` for compatibility
with earlier callers.

```python
from phi_boundary_gate import PhiBoundaryGateError, PolicyError, ProjectConfigError, TraceMappingError

try:
    gate = PhiBoundaryGate.from_project()
except ProjectConfigError as exc:
    raise RuntimeError(f"project config is not ready: {exc}") from exc
except PolicyError as exc:
    raise RuntimeError(f"policy is not valid: {exc}") from exc
except PhiBoundaryGateError as exc:
    raise RuntimeError(f"PHI gate validation failed: {exc}") from exc
```

Use `TraceMappingError` for mapping validation and external trace conversion
failures. `ValueError` remains a broad fallback for projects that have not
adopted the typed exceptions yet. Missing project config discovery also remains
compatible with `FileNotFoundError` through `ProjectConfigNotFoundError`.

## Scan Only

```python
from phi_boundary_gate import ScanFinding, scan_text

findings = scan_text(
    "Member ID: MBR-SYN-8842",
    layer="model_input",
    policy=policy,
)

first: ScanFinding = findings[0]
assert first.category == "member_id"
payload = first.to_dict()
```

Each finding is a `ScanFinding` object with typed attributes for the matched value, span, detector confidence, policy disposition, and suggested redaction placeholder. Use `to_dict()` when a JSON-compatible shape is needed.

To add optional local Presidio-assisted NER spans, install the `ner` extra and
pass `enable_presidio=True`:

```python
findings = scan_text(
    "Casey Example called from (555) 013-4421.",
    layer="model_input",
    policy=policy,
    enable_presidio=True,
)
```

Presidio only contributes candidate spans. Policy disposition, redaction, and
blocking decisions still come from this package's policy engine.

## Redact Before Logging

```python
from phi_boundary_gate import guard_text, redact_text, scan_text

text = "debug member_id=MBR-SYN-8842"
findings = scan_text(text, layer="debug_log", policy=policy)
safe_log_text = redact_text(text, findings)
```

`redact_text` replaces the spans supplied by the caller. For log safety, callers should normally pass all PHI candidate findings.

## Guard Before Model Calls

```python
from phi_boundary_gate import guard_text

decision = guard_text(
    "Summarize claim CLM-SYN-44501",
    layer="model_input",
    policy=policy,
    mode="block_on_violation",
    enable_presidio=True,
)

if decision.should_block:
    raise RuntimeError(decision.recommended_action)

model_text = decision.redacted_text if decision.should_redact else decision.text
payload = decision.to_safe_dict()
```

`guard_text` handles PHI detection and layer policy only. Use `guard_compliance` when a project also needs to enforce BAA, covered service, model, feature, logging, and storage eligibility.

`GuardDecision.to_dict()` preserves the original detailed shape and includes the
raw input text and raw finding values. Use it only where raw PHI handling is
approved. Use `to_safe_dict()` for audit logs, application logs, and routine
telemetry.

## Guard Before Covered Service Calls

```python
from pathlib import Path

from phi_boundary_gate import ComplianceContext, guard_compliance, load_compliance_policy

compliance_policy = load_compliance_policy(Path("config/phi-compliance-policy.yml"))
decision = guard_compliance(
    "member_id=MBR-SYN-8842",
    layer="model_input",
    phi_policy=policy,
    compliance_policy=compliance_policy,
    context=ComplianceContext(
        phi_status="real_phi",
        vendor="google",
        service="vertex_ai",
        endpoint="generate_content",
        model="gemini-2.5-pro",
        feature="online_prediction",
        environment="production",
        logging="redacted_only",
        storage="none",
    ),
    enable_presidio=True,
)

if decision.should_block:
    raise RuntimeError(decision.block_reasons)

audit_payload = decision.to_dict()
```

`guard_compliance` does not discover contract status. It enforces the BAA and service facts supplied by the calling organization's compliance policy.

## Guard Modes

`guard_text` supports three modes:

- `report_only`: default. Scan and return policy decisions, but do not recommend blocking or redacting the model input.
- `redact`: set `should_redact` when PHI candidates were replaced in `redacted_text`.
- `block_on_violation`: set `should_block` when any finding has policy disposition `violation`.

`redacted_text` is always available for safe logging, even when `should_redact` is false.

## Integration Patterns

For a model-routing service, call `guard_text(..., layer="model_input")` before provider routing. Use `should_block` to enforce project-level PHI mode and provider eligibility. Use `redacted_text` for logs and error summaries.

For an agent runtime, call `guard_text` around trace and log boundaries such as user messages, tool results, assembled model input, and compaction memory. Use `redacted_text` for ordinary logs and keep full boundary reports for synthetic or approved traces only.

For CI or offline audit, keep `mode="report_only"` for text guards and use
`audit_trace()`, `audit_events()`, or the CLI report outputs for full traces.

## Direct External Trace Audit

For mapped external agent traces, the SDK facade can compose normalization and
path-aware auditing without persisting an intermediate trace:

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()
result = gate.audit_external_trace(
    "raw-agent-events.jsonl",
    mapping="config/phi-trace-map.yml",
    diagnostics_path="/tmp/phi-adapter-diagnostics.json",
    report_value_mode="redacted",
)
```

The report keeps `raw-agent-events.jsonl` as its `trace_path`, while findings
retain adapter provenance through `external_content_path`. Use the lower-level
`TraceAdapter` flow below when you explicitly need the normalized events or a
persisted normalized JSONL artifact.

## External Trace Conversion

External agent logs can be normalized through mapping v1 before scanning. New
integrations should prefer the public `TraceAdapter` facade:

```python
from phi_boundary_gate import TraceAdapter, TraceMappingError

try:
    adapter = TraceAdapter.from_mapping("config/phi-trace-map.yml")
    events = adapter.load("raw-agent-events.jsonl")
    adapter.write("raw-agent-events.jsonl", "/tmp/phi-normalized-trace.jsonl")
except TraceMappingError as exc:
    raise RuntimeError(f"external trace normalization failed: {exc}") from exc
```

Function-style helpers remain available:

```python
from pathlib import Path

from phi_boundary_gate import build_conversion_diagnostics, load_external_trace, load_trace_mapping, write_converted_trace

events = load_external_trace(
    Path("raw-agent-events.jsonl"),
    Path("config/phi-trace-map.yml"),
)

write_converted_trace(
    Path("raw-agent-events.jsonl"),
    Path("config/phi-trace-map.yml"),
    Path("/tmp/phi-normalized-trace.jsonl"),
)

diagnostics = build_conversion_diagnostics(
    Path("raw-agent-events.jsonl"),
    load_trace_mapping(Path("config/phi-trace-map.yml")),
)
```

The returned `TraceEvent` objects use the same shape as `load_trace()`. See
[Trace Adapters](adapters.md) for the mapping schema and CLI flow.

When building reports for real or approved non-synthetic traces, prefer
`audit_trace(..., report_value_mode="redacted")`,
`audit_events(..., report_value_mode="redacted")`,
`build_report(..., report_value_mode="redacted")`, or
`report_value_mode="hashed"` so stored Markdown and JSON reports do not display
raw matched values. The default remains `raw` for compatibility.

Runnable SDK and adapter examples are kept in [../examples](../examples), and CI
executes them against the installed package smoke path.

## CLI Redacted Trace

From this repository root:

```bash
PYTHONPATH=src python3 -m phi_boundary_gate.cli \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
```

The equivalent subcommand form is:

```bash
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
```

The redacted trace preserves synthetic event metadata and replaces `content` values with policy redaction placeholders. If a value is detected anywhere in the trace, exact repeats of that value are also replaced across the redacted trace.

## Boundary

This package reports PHI candidates from automated detection. It does not provide a HIPAA compliance guarantee and does not replace legal, compliance, or security review.
