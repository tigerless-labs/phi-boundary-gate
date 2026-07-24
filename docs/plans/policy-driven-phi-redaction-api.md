# Policy-Driven PHI Redaction API Plan

## Goal

Expose the PHI scanner and redaction behavior as a lightweight Python API that other projects can import before model calls, log writes, or trace exports.

## Scope

- Add public `scan_text`, `redact_text`, `guard_text`, and `load_policy` exports.
- Add a span-based redaction engine using policy redaction placeholders.
- Add a guard decision object for application code.
- Add optional CLI redacted trace output.
- Document library use cases for scan-only, redact-before-logging, and guard-before-model-call flows.
- Add tests for scanning, redaction, guard decisions, and redacted trace output.

## Acceptance

- Other Python projects can import the package and scan/redact/guard a text string.
- Redaction replaces all supplied candidate spans with policy placeholders.
- No-PHI text remains unchanged.
- CLI report generation behavior remains compatible by default.
- Passing `--redacted-trace` writes a synthetic JSONL trace with redacted `content`.

## Non-Goals

- No external detector backend integration.
- No BAA provider registry.
- No real PHI samples.
- No HTTP sidecar service.
- No consumer-project integration changes.
