# PHI Context Boundary Report

PHI Context Boundary Report is a lightweight developer-facing audit tool direction for healthcare and insurance AI workflows.

It answers one practical question:

> Did PHI enter the prompt, RAG context, tool output, memory, or logs?

The project starts with synthetic data only. It does not provide legal compliance guarantees and does not process real PHI in the repository.

## What it does

Planned first version:

- read a synthetic agent trace in JSONL format
- read a PHI policy in YAML format
- detect PHI candidates across context layers
- track source and destination paths
- output Markdown and JSON reports
- suggest redaction for risky fields

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

Initial documentation scaffold. Implementation will be added after the MVP contract is reviewed.
