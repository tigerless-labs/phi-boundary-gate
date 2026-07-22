# Library API

The package can be imported by other Python projects that need lightweight PHI candidate scanning, policy decisions, redaction, or model-call guard checks.

## Load Policy

```python
from pathlib import Path

from phi_boundary_report import load_policy

policy = load_policy(Path("samples/policies/default.yml"))
```

## Scan Only

```python
from phi_boundary_report import ScanFinding, scan_text

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

## Redact Before Logging

```python
from phi_boundary_report import guard_text, redact_text, scan_text

text = "debug member_id=MBR-SYN-8842"
findings = scan_text(text, layer="debug_log", policy=policy)
safe_log_text = redact_text(text, findings)
```

`redact_text` replaces the spans supplied by the caller. For log safety, callers should normally pass all PHI candidate findings.

## Guard Before Model Calls

```python
from phi_boundary_report import guard_text

decision = guard_text(
    "Summarize claim CLM-SYN-44501",
    layer="model_input",
    policy=policy,
    mode="block_on_violation",
)

if decision.should_block:
    raise RuntimeError(decision.recommended_action)

model_text = decision.redacted_text if decision.should_redact else decision.text
payload = decision.to_dict()
```

`guard_text` does not decide whether a provider or model is covered by a BAA. Calling projects must enforce provider eligibility, endpoint configuration, logging, retention, and access-control requirements.

## Guard Modes

`guard_text` supports three modes:

- `report_only`: default. Scan and return policy decisions, but do not recommend blocking or redacting the model input.
- `redact`: set `should_redact` when PHI candidates were replaced in `redacted_text`.
- `block_on_violation`: set `should_block` when any finding has policy disposition `violation`.

`redacted_text` is always available for safe logging, even when `should_redact` is false.

## Integration Patterns

For `ai_translation`, call `guard_text(..., layer="model_input")` before provider routing. Use `should_block` to enforce project-level PHI mode and provider eligibility. Use `redacted_text` for logs and error summaries.

For `lara`, call `guard_text` around trace/log boundaries such as user messages, tool results, assembled model input, and compaction memory. Use `redacted_text` for ordinary logs and keep full boundary reports for synthetic or approved traces only.

For CI or offline audit, keep `mode="report_only"` and use the CLI report outputs.

## CLI Redacted Trace

```bash
PYTHONPATH=src python3 -m phi_boundary_report.cli \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
```

The redacted trace preserves synthetic event metadata and replaces `content` values with policy redaction placeholders. If a value is detected anywhere in the trace, exact repeats of that value are also replaced across the redacted trace.

## Boundary

This package reports PHI candidates from automated detection. It does not provide a HIPAA compliance guarantee and does not replace legal, compliance, or security review.
