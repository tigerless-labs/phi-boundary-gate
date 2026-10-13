# Changelog

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
