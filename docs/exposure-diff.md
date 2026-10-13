# Exposure Diff

Exposure Diff compares two existing JSON audit reports and describes how observed PHI
candidate routes changed between runs. It is advisory analysis: differences never change
the command's successful exit status, block CI, rewrite a trace, or modify a policy.

## Run the synthetic example

From the repository root, generate both reports with the existing scanner and then compare
them:

```bash
mkdir -p /tmp/phi-exposure-diff

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_baseline.jsonl \
  --policy samples/policies/default.yml \
  --report-values redacted \
  --out /tmp/phi-exposure-diff/before.md \
  --json /tmp/phi-exposure-diff/before.json

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_candidate.jsonl \
  --policy samples/policies/exposure_diff_candidate.yml \
  --report-values redacted \
  --out /tmp/phi-exposure-diff/after.md \
  --json /tmp/phi-exposure-diff/after.json

PYTHONPATH=src python3 -m phi_boundary_gate.cli compare-reports \
  --before /tmp/phi-exposure-diff/before.json \
  --after /tmp/phi-exposure-diff/after.json \
  --out /tmp/phi-exposure-diff/diff.md \
  --json /tmp/phi-exposure-diff/diff.json

sed -n '1,220p' /tmp/phi-exposure-diff/diff.md
python3 -m json.tool /tmp/phi-exposure-diff/diff.json
```

The example produces one newly observed `name` route, one no-longer-observed `claim_id`
route, and a frequency and policy-disposition change for the existing `member_id` route.
Because the reports refer to different policies, the result is explicitly `limited`: the
disposition change must not be attributed solely to Agent behavior.

## Canonical exposure key

Diff schema v1 expands every finding once per unique destination. A finding without a
destination receives one explicit no-destination route. Each route key contains only:

- candidate category;
- source layer;
- SHA-256 references for source type and source path;
- destination layer and a SHA-256 reference for destination path;
- SHA-256 references for `content_path` and `external_content_path`.

Schema v3 `boundary_exposures` group findings by category and matched value. Exposure Diff
instead reconstructs route groups from validated `findings`, because matched-value identity is
both sensitive and the wrong key for comparing structural flow. The existing exposure summaries
remain unchanged and are never rewritten.

The key deliberately excludes event ID, timestamp, matched value, value hash, span, finding
ID, report-local exposure ID, policy rule text, detector reason, and semantic output. Event
ordering and timestamp changes therefore do not change route identity. Repeated routes are
counted, while exact duplicate destinations on one finding are counted once.

JSON array indexes are retained in the path input before hashing. This conservative exact
matching avoids combining distinct array positions, but an array reorder can appear as a new
and no-longer-observed pair. Diff schema v1 does not guess that the two positions are the same.

`occurrences` counts finding-to-destination observations. `events` counts distinct report-local
event IDs within one route. Event IDs contribute only to that per-report count; they are never
copied to the Diff or used for cross-report identity. Exposure group counts are the number of
distinct canonical route keys, not event counts.

## Validation and safe output

Both inputs must be current path-aware audit reports (`schema_version: 3`,
`finding_schema: path-aware`). The reader validates the schema-defined fields used by the
comparison. Invalid JSON, missing required fields, unsupported categories/layers/dispositions,
or an incompatible schema return the CLI's normal validation error status (`2`). Differences
between two valid reports return `0`, including newly observed or more severe routes.

The Diff has its own versioned JSON contract (`schema_version: 1`). It never copies matched
values, raw trace text, event IDs, free-form detector or policy reasons, semantic rationale,
unknown input fields, source types, or input paths. Potentially sensitive structural strings are
represented only by SHA-256 references. Before and after report identifiers are content
references rather than filenames.

The comparison is deterministic and does not modify either input report.

## Comparability limits

Audit report schema v3 records a policy path, but not a fingerprint of policy contents or
detector configuration. Exposure Diff therefore reports `comparable_with_limitations` even when
the policy references match, and `limited` when they differ. A changed disposition is an observed
report difference; it is not proof that the Agent changed.

Semantic Context Gate metadata is optional and remains disabled by default. Exposure Diff does
not invoke an LLM, external provider, or resolver, compare semantic decisions, lower a policy disposition, or change the
resolver injection API. Mismatched or partial semantic coverage is reported as limited and
semantic fields are excluded from the canonical key and output.

`New Exposure` means that a candidate route appears only in the after report. It is not automatic
proof of a new real-world PHI leak. `No Longer Observed` means only that a route is absent from the
after report; it is not proof that the underlying risk was eliminated. This tool performs neither
cross-event identity resolution nor HIPAA compliance determination.
