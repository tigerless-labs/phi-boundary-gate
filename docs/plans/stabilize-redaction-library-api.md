# Stabilize Redaction Library API Plan

## Goal

Make the public Python API easier for other projects to integrate by replacing dict-first scan results with typed objects while preserving JSON-compatible output shapes.

## Scope

- Add `ScanFinding` as the typed scan result.
- Keep `ScanFinding.to_dict()` compatible with the existing finding shape.
- Add `GuardDecision.to_dict()`.
- Add `should_block` and `should_redact` to guard decisions.
- Add `guard_text` modes: `report_only`, `redact`, and `block_on_violation`.
- Keep CLI, report, and redacted trace behavior compatible.

## Acceptance

- Existing CLI and report tests still pass.
- `scan_text` returns `ScanFinding` objects.
- `redact_text` works with typed findings and legacy dict-shaped findings.
- `guard_text(mode="block_on_violation")` sets `should_block` for policy violations.
- `guard_text(mode="redact")` sets `should_redact` when redaction changes text.

## Non-Goals

- No provider or model BAA eligibility registry.
- No consumer-project integration changes.
- No detector backend changes.
- No report schema changes.
