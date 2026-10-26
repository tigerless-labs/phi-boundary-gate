# Report Format

The CLI writes both Markdown and JSON reports.

The separate Exposure Diff contract compares two JSON audit reports without changing this
schema. See [Exposure Diff](exposure-diff.md).

The optional v0.8.2 Exposure Regression Review is a separate Markdown rendering
derived from the Diff result. It does not add fields to Audit Report schema v3
or Diff schema v1. It contains only aggregate counts and fixed guidance text,
remains advisory/non-blocking, and is not a HIPAA compliance certification.

The optional v0.8.3 Audit Coverage output is also a separate JSON/Markdown
contract. It does not add fields to Audit Report schema v3 and contains no
findings or raw trace data. See [Audit Coverage Diagnostics](audit-coverage.md).

## JSON Report

Top-level fields:

- `schema_version`: Report schema version. The current report writes `3`.
- `report_value_mode`: How matched values are displayed: `raw`, `redacted`, or
  `hashed`.
- `finding_schema`: Finding schema family. Schema v3 writes `path-aware`.
- `trace_path`: Input trace path.
- `policy_path`: Input policy path.
- `audit_context`: Optional schema-v3 provenance written by v0.8.1 and newer.
  It records fingerprint version `1`, SHA-256 fingerprints of normalized
  effective policy and detector configuration, Presidio enablement/configuration
  status, and Semantic Resolver enablement/configuration status.
- `summary`: Finding counts by disposition and risk, plus
  `by_semantic_disposition` when semantic analysis is enabled.
- `findings`: Array of PHI candidate findings.
- `boundary_exposures`: Array of grouped PHI boundary exposure summaries.

`policy_fingerprint` is independent of YAML field order and policy path. It
includes decision-relevant policy fields after parsing. `detector_fingerprint`
includes the bundled detector rules and Presidio enablement. When Presidio is
enabled, external Analyzer/model configuration is marked `unknown` because the
audit pipeline cannot verify it.

SDK callers may pass a stable, non-sensitive `semantic_resolver_id`. The report
stores only its SHA-256 fingerprint. When a resolver is enabled without an ID,
semantic configuration is `unknown`. Reports never put the original identifier,
raw PHI, prompts, secrets, or free-form resolver reasons in `audit_context`.

The field is optional so existing v0.8.0 schema-v3 reports remain valid.

```json
{
  "audit_context": {
    "fingerprint_version": 1,
    "policy_fingerprint": "sha256:<64 lowercase hex characters>",
    "detector_fingerprint": "sha256:<64 lowercase hex characters>",
    "presidio_enabled": false,
    "presidio_configuration": "not_applicable",
    "semantic_enabled": false,
    "semantic_resolver_fingerprint": null,
    "semantic_configuration": "not_applicable"
  }
}
```

## Finding Object

Each finding contains:

- `finding_id`: Stable report-local identifier.
- `event_id`: Source trace event ID.
- `layer`: Context layer where the candidate was found.
- `category`: Candidate category.
- `value`: Display value for the configured `report_value_mode`.
- `value_display`: Same display value used by Markdown rendering.
- `value_hash`: Stable `sha256:` hash of the matched value.
- `span`: Character offsets in the scanned text segment. For structured JSON
  content, this is the scalar leaf text, not the whole event content string.
- `content_path`: JSON-style path to the scanned leaf when event `content` is a
  JSON object or array string. Plain text events use `null`.
- `external_content_path`: Adapter-facing path when the trace event has exactly
  one `metadata.external_content_paths` base and it can be combined with
  `content_path`.
- `confidence`: Detector confidence from `0` to `1`.
- `reason`: Detector reason.
- `source`: Trace source object.
- `destinations`: Trace destinations array.
- `policy`: Policy disposition and risk.
- `redaction`: Suggested redaction action and replacement value.
- `semantic`: Optional bounded semantic metadata when a resolver is enabled:
  `subject_role`, `information_role`, `linkage`, `disposition`, and `confidence`.
  Free-form resolver reasons and chain-of-thought are never written to reports.

## Boundary Exposure Object

Boundary exposures group repeated findings by raw candidate value before report
display values are applied. Each object contains:

- `exposure_id`: Stable report-local identifier.
- `category`: Candidate category.
- `value`: Display value for the configured `report_value_mode`.
- `value_display`: Same display value used by Markdown rendering.
- `value_hash`: Stable `sha256:` hash of the matched value.
- `finding_ids`: Findings included in the group.
- `event_ids`: Trace events where the candidate appeared.
- `layers_seen`: Context layers in first-seen order.
- `content_paths_seen`: Unique structured content paths where the candidate was
  seen.
- `external_content_paths_seen`: Unique adapter-facing paths where the candidate
  was seen.
- `first_seen_event_id`: First event where the candidate appeared.
- `worst_disposition`: Most severe policy disposition for the candidate.
- `worst_layer`: Layer where the worst disposition appeared first.
- `recommended_boundary_action`: Suggested engineering action.
- `sources`: Unique trace source objects from grouped findings.
- `destinations`: Unique trace destination objects from grouped findings.

## Markdown Report

The Markdown report contains:

- Title and source paths.
- Summary counts.
- Boundary exposure summary.
- Findings table.
- Per-finding source and destination details.
- Per-finding content path and external content path details.
- Review note that all findings are candidates and require human review.

## Path-Aware Structured Content

Schema v3 keeps plain text traces compatible and adds precision for structured
payloads. If an event `content` value is a JSON object or array encoded as a
string, the scanner walks scalar leaves and records paths such as
`$.member_id`, `$.tool.response.claim_id`, or `$.messages[0].content`.

When an adapter records a single raw-payload base path in
`metadata.external_content_paths`, reports also include an `external_content_path`
such as `payload.tool.response.claim_id`. Multiple external bases remain
uncombined because a finding cannot be attributed to one raw field safely.

## Candidate Language

Reports must describe matches as PHI candidates, not confirmed PHI. Built-in
regex rules and optional local Presidio NER can both produce false positives or
false negatives, so findings still require caller controls and human review.
Use `scan-trace --report-values redacted` or `--report-values hashed` when
reports may be stored outside a PHI-approved location.

Semantic metadata is contextual evidence, not a legal determination. It never
downgrades detector or policy results in v0.7. Because a resolver receives the
current text segment and candidate value, external implementations may process
sensitive data even when the final report uses redacted or hashed display mode.
