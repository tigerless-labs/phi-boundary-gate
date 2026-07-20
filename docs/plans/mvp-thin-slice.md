# MVP Thin Slice Plan

## Goal

Turn the documentation scaffold into a runnable first version that reads a synthetic agent trace, applies a YAML policy, detects PHI candidates across context layers, and writes Markdown and JSON reports.

## Scope

- Define the first JSONL trace schema.
- Define the first YAML policy schema.
- Define the first Markdown and JSON report shape.
- Add one synthetic claim-agent trace.
- Add one synthetic PHI policy.
- Add a minimal Python CLI.
- Add focused standard-library tests.

## Inputs

- `samples/traces/claim_agent_minimal.jsonl`
- `samples/policies/default.yml`

## Outputs

- `reports/sample-report.md`
- `reports/sample-report.json`

## Acceptance

The CLI can answer these questions from synthetic data:

- What PHI candidates were found?
- Which trace event and context layer contained each candidate?
- What source and destination paths were associated with the event?
- Did the policy allow, require redaction, or flag a violation?
- What redaction value is suggested?

## Non-Goals

- No real PHI.
- No HIPAA compliance guarantee.
- No production middleware.
- No real-time blocking.
- No model, RAG, or logging integration.
- No advanced NLP detector.
