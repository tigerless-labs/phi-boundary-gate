# Detector Roadmap

This roadmap is driven by the trace corpus baseline. The detector should improve
coverage without erasing the distinction between candidate detection and policy
decision.

## Current Strengths

- Labeled healthcare and insurance IDs.
- Common US phone, email, SSN, address, ZIP, URL, and IPv4 patterns.
- Policy-driven layer decisions after detection.
- Boundary aggregation for repeated values across trace events.
- Optional local Presidio adapter for NER-backed candidate spans.

## Current Weaknesses

- Unlabeled names are best-effort without Presidio.
- Relative dates are not normalized.
- International and multilingual formats are mostly out of scope.
- Structured JSON payloads are scanned as strings rather than parsed by field path.
- False-positive suppression is corpus-based rather than policy-configurable.
- Reports can still contain raw matched values when callers scan real traces.

## Near-Term Work

1. Add report-value redaction or hashing for Markdown/JSON reports.
2. Add path-aware structured payload parsing for JSON-shaped trace content.
3. Move regex rules toward a reviewed rules file with deterministic loading.
4. Expand the false-positive near-miss corpus before adding broad weak patterns.
5. Add an international fixture pack with explicit non-goals by country/format.
6. Add a live optional Presidio smoke path outside default CI for environments that
   install NLP models.

## Non-Goals

- The detector does not certify HIPAA compliance.
- The detector does not prove a value is PHI; it reports candidates.
- The compliance guard does not discover BAA status or vendor terms.
- Default CI does not download NLP models.
