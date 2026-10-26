# Changelog

## 0.8.3

- Added opt-in JSON and Markdown audit coverage summaries for normalized trace
  events, observed layers, scannable segments, structured content, sources,
  destinations, and provider destinations.
- Added bounded advisory blind-spot diagnostics, including explicit expected
  layer checks and aggregate external mapping evidence without raw content,
  paths, keys, or inferred dropped-event counts.
- Added `--coverage-json`, `--coverage-markdown`, and repeatable
  `--expect-layer` options to `scan-trace` and `scan-external-trace`, plus
  matching standalone and facade SDK APIs.
- Preserved Audit Report schema v3, detector, Guard, redaction, Exposure Diff,
  default CLI output, CI behavior, and success exit codes for coverage warnings.

Coverage describes only the normalized input observed by the audit. It does not
prove execution completeness; zero findings does not prove an execution was
PHI-free; and a coverage warning is not a HIPAA noncompliance determination.

## 0.8.2

- Added an optional, bounded Markdown Exposure Regression Review for GitHub Job
  Summary and PR review workflows.
- Added fixed machine-readable guidance codes for newly observed routes,
  disposition direction, and policy, detector, or semantic comparability limits.
- Added `--review-summary` to `compare-reports` plus matching
  `ExposureDiffResult` SDK helpers; the existing Diff JSON and Markdown remain
  unchanged when the option is omitted.
- Kept all observed changes advisory and non-blocking. Frequency changes do not
  imply worsening, no-longer-observed routes do not prove elimination, and the
  summary cannot override Guard, compliance, policy, or CI decisions.

## 0.8.1

- Added optional Audit Report Schema v3 `audit_context` provenance with stable
  fingerprints for normalized effective policy and detector configuration.
- Added explicit Presidio and Semantic Resolver configuration evidence;
  unverifiable external analyzer/model state and unidentified resolver state are
  reported as unknown rather than inferred.
- Added structural and disposition comparability diagnostics, machine-readable
  reason codes, same-reference policy-content drift detection, and recognition
  of equivalent policies loaded from different paths.
- Added `worsened`, `improved`, and `mixed_or_other` direction to changed
  disposition groups and matching summary counts.
- Preserved compatibility with v0.8.0 schema-v3 reports by accepting missing
  provenance and marking the comparison limited.

Exposure Diff remains advisory: differences do not create a CI hard gate,
change Guard decisions, or establish that Agent behavior caused an observed
change. Reports and Diffs do not add raw PHI, prompts, secrets, resolver
rationale, or unhashed route paths.

## 0.8.0

- Added advisory JSON/Markdown Exposure Diff reports for comparing two schema v3
  audit reports.
- Added exact structural route keys, per-destination expansion, disposition and
  frequency changes, stable ordering, and explicit comparability warnings.
- Added safe path/source references that prevent the Diff from copying raw PHI,
  raw trace content, free-form reasons, or untrusted input fields.
- Preserved all existing scan, Guard, and optional Semantic Context Gate behavior.

## 0.7.0

- Added the provider-neutral Semantic Context Gate with validated subject role,
  information role, linkage, disposition, confidence, and concise reason.
- Added explicit SDK resolver injection for scans, guards, compliance checks,
  normalized trace audits, and external trace audits.
- Added fail-safe handling: semantic outcomes and resolver failures never
  downgrade existing detector or boundary-policy decisions.
- Added bounded semantic metadata to JSON and Markdown reports without storing
  free-form resolver reasons or chain-of-thought.
- Added synthetic semantic contrast, schema, failure, report, and regression
  coverage.

Semantic analysis remains disabled by default. This release does not add
cross-event identity linking, coreference, entity graphs, or longitudinal
patient/member context.
