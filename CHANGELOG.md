# Changelog

## 0.3.2 - 2026-07-29

- Added a synthetic trace corpus baseline for false-positive near misses, free-text PHI variants, structured payloads, and provider-boundary flows.
- Added expectation YAML contracts for every valid trace fixture.
- Added a trace corpus coverage report tool and committed `reports/trace-corpus-coverage.json` baseline.
- Added trace corpus tests that validate expectations and keep the committed coverage baseline current.
- Documented the trace corpus coverage matrix and detector roadmap.

## 0.3.1 - 2026-07-28

- Added GitHub Actions CI for unit tests, release guard tests, compile checks, CLI smoke runs, and package smoke installation.
- Added a release version guard that checks package version copies and requires a version bump when shipped surface changes.
- Added repository quality tests for README version/install/safety content and detector-category coverage in the sample policy.
- Documented update guidance and operational safety boundaries in the README.

## 0.3.0 - 2026-07-28

- Expanded built-in regex detection for broader synthetic PHI variants:
  - phone and fax formats
  - email addresses
  - SSNs
  - street addresses, PO boxes, and ZIP codes
  - individual-related healthcare dates
  - member/subscriber, claim/authorization, MRN, policy, group, account, license, vehicle, and device identifiers
  - URLs and IPv4 addresses
- Added optional local Presidio-assisted NER detection behind explicit `enable_presidio=True` API parameters and the CLI `--enable-presidio` flag.
- Added optional `ner` dependency extra for Presidio/spaCy integration without changing the default lightweight install.
- Added span merging so deterministic regex findings take precedence over overlapping Presidio findings.
- Added an expanded synthetic trace fixture and hybrid detection tests.
- Updated sample policy categories, docs, and install examples for `v0.3.0`.

## 0.2.0 - 2026-07-23

- Added typed compliance eligibility guard API:
  - `ComplianceContext`
  - `ComplianceDecision`
  - `CompliancePolicy`
  - `ServiceProfile`
  - `guard_compliance`
  - `load_compliance_policy`
- Added organization-supplied policy checks for BAA confirmation, covered service status, model patterns, features, logging, and storage.
- Added audit-safe `ComplianceDecision.to_dict()` output that omits raw PHI by default.
- Added synthetic compliance policy sample and compliance guard documentation.
- Kept existing CLI, report, redacted trace, and `guard_text` behavior compatible.

## 0.1.0 - 2026-07-22

- Added synthetic trace and PHI policy schemas.
- Added CLI for Markdown and JSON PHI boundary reports.
- Added detector-driven candidate findings across agent context layers.
- Added boundary exposure summaries.
- Added policy-driven redaction helpers and redacted trace output.
- Added typed scan/redaction library API with `ScanFinding`, `GuardDecision`, `scan_text`, `redact_text`, and `guard_text`.
