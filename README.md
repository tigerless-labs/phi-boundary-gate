# PHI Context Boundary Report

PHI Context Boundary Report is a lightweight developer-facing audit tool direction for healthcare and insurance AI workflows.

It answers one practical question:

> Did PHI enter the prompt, RAG context, tool output, memory, or logs?

The project starts with synthetic data only. It does not provide legal compliance guarantees and does not process real PHI in the repository.

## What it does

First version:

- read a synthetic agent trace in JSONL format
- read a PHI policy in YAML format
- detect PHI candidates across context layers
- track source and destination paths
- output Markdown and JSON reports
- suggest redaction for risky fields

## Quick start

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
  --json reports/sample-report.json
```

Run the MVP tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Context layers

The first version focuses on:

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

## Non-goals

- no real PHI
- no HIPAA compliance guarantee
- no medical decision-making
- no production middleware in the first version
- no automatic blocking in the first version

## Development status

Runnable MVP thin slice with synthetic samples, policy-driven layer decisions, and Markdown/JSON reports.
