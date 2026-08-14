# Report Format

The CLI writes both Markdown and JSON reports.

## JSON Report

Top-level fields:

- `schema_version`: Report schema version. The current report writes `2`.
- `report_value_mode`: How matched values are displayed: `raw`, `redacted`, or
  `hashed`.
- `trace_path`: Input trace path.
- `policy_path`: Input policy path.
- `summary`: Finding counts by disposition and risk.
- `findings`: Array of PHI candidate findings.
- `boundary_exposures`: Array of grouped PHI boundary exposure summaries.

## Finding Object

Each finding contains:

- `finding_id`: Stable report-local identifier.
- `event_id`: Source trace event ID.
- `layer`: Context layer where the candidate was found.
- `category`: Candidate category.
- `value`: Display value for the configured `report_value_mode`.
- `value_display`: Same display value used by Markdown rendering.
- `value_hash`: Stable `sha256:` hash of the matched value.
- `span`: Character offsets in the event content.
- `confidence`: Detector confidence from `0` to `1`.
- `reason`: Detector reason.
- `source`: Trace source object.
- `destinations`: Trace destinations array.
- `policy`: Policy disposition and risk.
- `redaction`: Suggested redaction action and replacement value.

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
- Review note that all findings are candidates and require human review.

## Candidate Language

Reports must describe matches as PHI candidates, not confirmed PHI. Built-in
regex rules and optional local Presidio NER can both produce false positives or
false negatives, so findings still require caller controls and human review.
Use `scan-trace --report-values redacted` or `--report-values hashed` when
reports may be stored outside a PHI-approved location.
