# Report Format

The MVP writes both Markdown and JSON reports.

## JSON Report

Top-level fields:

- `schema_version`: Report schema version. The MVP writes `1`.
- `trace_path`: Input trace path.
- `policy_path`: Input policy path.
- `summary`: Finding counts by disposition and risk.
- `findings`: Array of PHI candidate findings.

## Finding Object

Each finding contains:

- `finding_id`: Stable report-local identifier.
- `event_id`: Source trace event ID.
- `layer`: Context layer where the candidate was found.
- `category`: Candidate category.
- `value`: Matched synthetic value.
- `span`: Character offsets in the event content.
- `confidence`: Detector confidence from `0` to `1`.
- `reason`: Detector reason.
- `source`: Trace source object.
- `destinations`: Trace destinations array.
- `policy`: Policy disposition and risk.
- `redaction`: Suggested redaction action and replacement value.

## Markdown Report

The Markdown report contains:

- Title and source paths.
- Summary counts.
- Findings table.
- Per-finding source and destination details.
- Review note that all findings are candidates and require human review.

## Candidate Language

Reports must describe matches as PHI candidates, not confirmed PHI. The MVP detector is rule-based and may produce false positives or false negatives.
