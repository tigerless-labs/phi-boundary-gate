<h1 align="center">PHI Context Boundary Report</h1>

<p align="center">
  <img src="https://img.shields.io/badge/release-v0.2.0-brightgreen.svg" alt="release v0.2.0" />
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/output-Markdown%20%7C%20JSON%20%7C%20JSONL-lightgrey.svg" alt="Markdown, JSON, and JSONL output" />
  <img src="https://img.shields.io/badge/data-synthetic%20PHI%20only-yellow.svg" alt="synthetic PHI only" />
</p>

**PHI Context Boundary Report** scans synthetic agent traces and shows where PHI
candidates cross context boundaries: user messages, RAG context, tool output,
model input, memory, debug logs, and provider requests.

It is built for healthcare and insurance AI workflows where an identifier match
is only the start. The report answers which layer the value entered, where it
came from, where it is going, and what policy says should happen before it moves
again.

The package ships as both a CLI and a Python library. Use the CLI for offline
audits that produce Markdown, JSON, and redacted JSONL traces. Use the library
inside another service to scan text, redact policy-matched spans, or block model
calls when the configured PHI and compliance policy says the route is not allowed.

| | |
|---|---|
| **Boundary-first reports** | Groups repeated PHI candidates across trace events so you can see the path, not only the match. |
| **Policy-driven redaction** | YAML policy decides whether each category is allowed, should be redacted, or is a violation in each layer. |
| **Provider-call guard** | Checks organization-supplied BAA, covered service, model, feature, logging, and storage facts before PHI is sent. |
| **Audit-safe by default** | Compliance decisions can be serialized without raw PHI values unless controlled debugging explicitly asks for them. |
| **Synthetic samples only** | The repository contains no real PHI and does not claim HIPAA compliance. |

## Quick Start

For package installation options, including Git tag installs for other projects,
see [Install and Consume as a Package](docs/install.md). For release notes, see
[CHANGELOG](CHANGELOG.md).

```bash
python3 -m pip install -e .
phi-boundary-report \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json
```

Run the same command without installing the package:

```bash
PYTHONPATH=src python3 -m phi_boundary_report.cli \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
```

Invalid trace or policy input returns exit code `2` and writes the validation
error to stderr.

## What It Reads

The trace is JSONL. Each event records the layer, content, source path, and
destination path for one piece of context:

```json
{"event_id":"evt_003","timestamp":"2026-01-15T09:00:03Z","layer":"tool_output","source":{"type":"synthetic_claim_lookup","path":"tools.claim_lookup.response"},"destinations":[{"layer":"model_input","path":"prompt.context[1]"},{"layer":"debug_log","path":"logs.debug.claim_lookup"}],"content":"Lookup result: claim_id=CLM-SYN-44501 member_id=MBR-SYN-8842 mrn=MRN-SYN-22091 address=101 Example Harbor Rd."}
```

Supported source layers:

- `user_message`
- `rag_context`
- `tool_output`
- `model_input`
- `memory`
- `debug_log`

Destination paths may also point at `model_provider`.

The PHI policy is YAML. It maps detector categories to layer decisions:

```yaml
version: 1
categories:
  member_id:
    description: Synthetic insurance member identifier.
    high_risk: true
    deny_layers:
      - debug_log
    redact_layers:
      - model_input
      - rag_context
      - tool_output
      - memory
    redaction: "[REDACTED_MEMBER_ID]"
```

See [Trace Schema](docs/trace-schema.md) and [Policy Schema](docs/policy-schema.md)
for the full contract.

## What It Reports

The CLI writes two report formats from the same scan:

- Markdown for human review, with summary counts, boundary exposures, findings,
  sources, destinations, and recommended actions.
- JSON for CI, dashboards, or downstream audit storage.

Each finding includes the matched value, category, span, detector confidence,
trace source, trace destinations, policy disposition, risk level, and suggested
redaction value. Boundary exposures group the same PHI candidate across events,
then sort by the worst policy disposition so violations rise to the top.

When `--redacted-trace` is provided, the CLI also writes a JSONL trace whose
`content` fields use policy redaction placeholders. Exact repeats of a detected
value are replaced across the trace.

## Library API

Other Python projects can import the scanner and redactor directly:

```python
from pathlib import Path

from phi_boundary_report import guard_text, load_policy

policy = load_policy(Path("samples/policies/default.yml"))
decision = guard_text(
    "member_id=MBR-SYN-8842",
    layer="debug_log",
    policy=policy,
    mode="block_on_violation",
)

if decision.should_block:
    raise RuntimeError(decision.recommended_action)

safe_text = decision.redacted_text
```

`guard_text` handles PHI detection and layer policy only. It supports
`report_only`, `redact`, and `block_on_violation` modes. See
[Library API](docs/library-api.md) for the typed `ScanFinding` and
`GuardDecision` shapes.

## Compliance Guard

Projects that route PHI to covered services can run the compliance guard before
provider calls:

```python
from pathlib import Path

from phi_boundary_report import (
    ComplianceContext,
    guard_compliance,
    load_compliance_policy,
    load_policy,
)

phi_policy = load_policy(Path("samples/policies/default.yml"))
compliance_policy = load_compliance_policy(Path("samples/compliance_policies/default.yml"))

decision = guard_compliance(
    "member_id=MBR-SYN-8842",
    layer="model_input",
    phi_policy=phi_policy,
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

if decision.should_block:
    raise RuntimeError(decision.block_reasons)

text_for_model = decision.redacted_text
audit_payload = decision.to_dict()
```

The guard enforces facts supplied by your organization. It cannot discover
whether a BAA is signed, whether a service is covered, or whether a vendor changed
its terms. Keep `samples/compliance_policies/default.yml` as a sample shape, not a
contract source of truth.

See [Compliance Guard](docs/compliance-guard.md) and
[Compliance Policy Schema](docs/compliance-policy-schema.md).

## Development

Run the tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Current release: `v0.2.0`.

## Limits

- No real PHI is stored in this repository.
- No HIPAA compliance guarantee is provided.
- No medical decision-making is performed.
- No automatic vendor contract discovery is attempted.
- Detector results are PHI candidates and need human review.
