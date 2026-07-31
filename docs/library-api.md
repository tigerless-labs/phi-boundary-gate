# Library API

The package can be imported by other Python projects that need lightweight PHI candidate scanning, policy decisions, redaction, or model-call guard checks.

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

For CI or offline audit, keep `mode="report_only"` and use the CLI report outputs.

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
