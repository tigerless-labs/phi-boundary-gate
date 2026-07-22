# PHI Context Boundary Report

PHI Context Boundary Report is a lightweight developer-facing audit tool direction for healthcare and insurance AI workflows.

It answers one practical question:

> Did PHI enter the prompt, RAG context, tool output, memory, or logs?

The project starts with synthetic data only. It does not provide legal compliance guarantees and does not process real PHI in the repository.

## What it does

Current version:

- read a synthetic agent trace in JSONL format
- read a PHI policy in YAML format
- detect PHI candidates across context layers
- track source and destination paths
- output Markdown and JSON reports
- suggest redaction for risky fields
- expose typed scan, redaction, and guard APIs for other Python projects
- enforce organization-supplied BAA, covered service, model, feature, logging, and storage eligibility policy before provider calls

## Quick start

For package installation options, including Git tag installs for other projects, see [Install and Consume as a Package](docs/install.md).
For release notes, see [CHANGELOG](CHANGELOG.md).

```bash
python3 -m pip install -e .
phi-boundary-report \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json
```

Without installing the package, run:

```bash
PYTHONPATH=src python3 -m phi_boundary_report.cli \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
```

Run the tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Invalid trace or policy input returns exit code `2` and writes the validation error to stderr.

## Context layers

The current context layers are:

- user message
- RAG context
- tool output
- model input
- memory
- debug log

## Example output

A report should show:

- what PHI candidates were found
- where each item came from
- which context layer it entered
- whether policy allows it
- what should be redacted

## Library use

Other Python projects can import the scanner and redactor directly:

```python
from pathlib import Path

from phi_boundary_report import guard_text, load_policy

policy = load_policy(Path("samples/policies/default.yml"))
decision = guard_text("member_id=MBR-SYN-8842", layer="debug_log", policy=policy)
safe_text = decision.redacted_text
```

Projects that route PHI to covered services can also use the compliance guard before provider calls:

```python
from phi_boundary_report import ComplianceContext, guard_compliance, load_compliance_policy

compliance_policy = load_compliance_policy(Path("samples/compliance_policies/default.yml"))
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
)
```

The compliance guard enforces organization-supplied policy facts. It cannot automatically know whether your company has signed a BAA.

## Non-goals

- no real PHI
- no HIPAA compliance guarantee
- no medical decision-making
- no automatic discovery of vendor contract status

## Development status

Runnable v0.2.0 package with synthetic samples, policy-driven layer decisions, redaction helpers, Markdown/JSON reports, and a configurable compliance eligibility guard.
