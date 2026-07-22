# PHI Compliance Eligibility Guard Plan

## Goal

Add a reusable guard that can block PHI before it enters services, models, features, logging, or storage paths that are not confirmed as approved by organization policy.

## Scope

- Add typed compliance context and decision objects.
- Add a YAML compliance policy loader.
- Add `guard_compliance()` that composes PHI detection with BAA and service eligibility checks.
- Add a synthetic sample compliance policy.
- Keep CLI and existing report behavior unchanged.
- Make audit serialization safe by default.

## Non-Goals

- No automatic vendor registry lookup.
- No legal or HIPAA compliance guarantee.
- No assumption that a company has signed a BAA.
- No integration PR in downstream projects.
- No LLM-based final compliance judgment.

## Acceptance Criteria

- PHI plus unknown service profile blocks by default.
- PHI plus unconfirmed BAA blocks when the PHI status requires BAA.
- PHI plus preview, beta, or experimental model blocks unless policy explicitly allows it.
- PHI plus denied feature, raw logging, or unsupported storage blocks.
- Non-PHI text is not blocked solely because the service profile is unknown.
- `ComplianceDecision.to_dict()` does not expose raw PHI by default.
