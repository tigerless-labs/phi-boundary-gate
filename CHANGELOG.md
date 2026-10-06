# Changelog

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
