# Validate Trace and Policy Contracts Plan

## Goal

Make synthetic trace and policy input failures predictable before adding broader detector coverage.

## Scope

- Validate destination path objects inside trace events.
- Validate policy layer names and category field types.
- Return a stable CLI error code for trace and policy input errors.
- Add no-PHI and invalid-input synthetic fixtures.
- Document validation behavior.

## Acceptance

- Valid synthetic trace and policy inputs still generate reports.
- A no-PHI trace generates a report with zero findings.
- Missing required trace content fails with a clear error.
- A policy category missing `redaction` fails with a clear error.
- Invalid policy layer names fail before report generation.
- `deny_layers` continues to take precedence over `redact_layers`.

## Non-Goals

- No detector category expansion.
- No report schema change.
- No CI setup.
- No real PHI samples.
- No nested JSON or adversarial trace scanning.
