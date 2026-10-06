# Semantic Context Gate

Version 0.7 adds optional semantic adjudication after candidate detection and
before the existing boundary policy result is returned:

```text
candidate
→ subject role
→ health/claim/payment linkage
→ semantic disposition
→ existing boundary policy
```

The gate is not another named-entity recognizer. Regex and optional Presidio
still locate candidate spans. A caller-supplied `SemanticResolver` receives one
candidate and its current text segment, then returns a `SemanticDecision`.

Supported values are:

- subject role: `patient`, `member`, `beneficiary`, `provider`, `clinician`,
  `unknown`;
- information role: `clinical`, `diagnosis`, `treatment`, `claim`, `payment`,
  `insurance`, `general`, `unknown`;
- linkage: `linked`, `unlinked`, `unclear`;
- semantic disposition: `likely_phi`, `likely_not_phi`, `uncertain`.

Confidence must be from `0` to `1`, and reason must be a non-empty concise
rationale. The reason is available to the in-process SDK caller but deliberately
omitted from JSON and Markdown reports.

## Safety invariant

Semantic analysis is disabled by default. When enabled, every semantic outcome
preserves the original detector finding and policy decision:

- `likely_phi` confirms contextual risk;
- `uncertain` cannot lower risk;
- `likely_not_phi` cannot lower risk;
- invalid output or an exception becomes `uncertain` with confidence `0`.

Version 0.7 has no downgrade option. This keeps redaction, violation, and block
behavior compatible with v0.6. The `NoopSemanticResolver` returns an `uncertain`
decision and is useful for integration tests.

## Data handling and scope

Candidate detection is not confirmed PHI, and semantic judgment is not a legal
determination. A resolver sees the current text segment and raw candidate value.
An external model may therefore receive sensitive data even if report display
mode is `redacted` or `hashed`; only use an approved provider and controls.

The project does not claim HIPAA compliance. Version 0.7 only adjudicates one
event/segment at a time. Cross-event identity linking, pronoun/coreference,
trace-level entity graphs, and longitudinal patient/member context remain out of
scope for v0.8 or later.
