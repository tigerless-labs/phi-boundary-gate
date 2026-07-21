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
from phi_boundary_report import scan_text

findings = scan_text(
    "Member ID: MBR-SYN-8842",
    layer="model_input",
    policy=policy,
)
```

Each finding includes the matched value, span, detector confidence, policy disposition, and suggested redaction placeholder.

## Redact Before Logging

```python
from phi_boundary_report import redact_text, scan_text

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
)

if decision.has_violations:
    raise RuntimeError(decision.recommended_action)

model_text = decision.redacted_text if decision.has_redactions else decision.text
```

`guard_text` does not decide whether a provider or model is covered by a BAA. Calling projects must enforce provider eligibility, endpoint configuration, logging, retention, and access-control requirements.

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
